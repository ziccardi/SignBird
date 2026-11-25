package io.github.ziccardi.signbird.documents;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

@Service
final class Jobs {
    record Owner(String issuer, String subject) {}
    record View(UUID jobId, String filename, String keyId, String credentialId, String status,
                String signatureScheme, Instant createdAt, Instant expiresAt) {}
    record Job(UUID id, String filename, String key, String credential, String status, String scheme,
               Instant createdAt, Instant expiresAt, String certificate, String chain, String digest) {
        View view() {
            var current = !expiresAt.isAfter(Instant.now()) ? "EXPIRED" : status;
            return new View(id, filename, key, credential, current, scheme, createdAt, expiresAt);
        }
    }
    record Download(String filename, InputStream stream, long byteCount) {}

    private static final Logger LOG = LoggerFactory.getLogger(Jobs.class);
    private static final Pattern STORED_NAME = Pattern.compile("([0-9a-f-]{36})\\.(source|p7m|partial)");
    private static final String COLUMNS = """
            job_id, filename, key_id, credential_id, status, scheme, created_at, expires_at, certificate_pem, chain_pem, digest
            """;
    private static final String OWNED = "SELECT " + COLUMNS + " FROM p7m_jobs WHERE job_id=? AND issuer=? AND subject=?";

    private final JdbcTemplate db;
    private final TransactionTemplate transactions;
    private final Peers peers;
    private final Path storage;
    private final int retentionHours;
    private final Cades cades = new Cades();

    Jobs(JdbcTemplate db, TransactionTemplate transactions, Peers peers,
         @Value("${SIGNBIRD_DOCUMENT_DIR:./data}") Path storage,
         @Value("${SIGNBIRD_P7M_RETENTION_HOURS:24}") int retentionHours) throws IOException {
        if (retentionHours < 1) throw new IllegalArgumentException("Invalid P7M retention");
        this.db = db;
        this.transactions = transactions;
        this.peers = peers;
        this.storage = Files.createDirectories(storage);
        this.retentionHours = retentionHours;
    }

    View upload(Owner owner, String bearer, String key, String credential, MultipartFile file) throws IOException {
        if (file.isEmpty()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A non-empty file is required");
        var certificate = peers.credential(bearer, key, credential);
        var id = UUID.randomUUID();
        String name = file.getOriginalFilename();
        name = name == null ? "" : name.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1).replaceAll("[\\p{Cntrl}]", "").strip();
        if (name.isEmpty()) name = "document";
        if (name.length() > 180) name = name.substring(0, 180);
        var source = path(id, "source");
        try (var input = file.getInputStream()) {
            Files.copy(input, source);
            sync(source);
        } catch (IOException error) {
            try {
                Files.deleteIfExists(source);
            } catch (IOException cleanupError) {
                error.addSuppressed(cleanupError);
            }
            throw error;
        }
        var job = db.queryForObject("""
                INSERT INTO p7m_jobs (job_id, issuer, subject, key_id, credential_id, filename,
                    certificate_pem, chain_pem, scheme) VALUES (?,?,?,?,?,?,?,?,?) RETURNING
                """ + COLUMNS, Jobs::row, id, owner.issuer(), owner.subject(), key, credential, name,
                certificate.certificate(), certificate.chain(), certificate.scheme());
        return job.view();
    }

    List<View> list(Owner owner) {
        return db.query("SELECT " + COLUMNS + " FROM p7m_jobs WHERE issuer=? AND subject=? ORDER BY created_at DESC LIMIT 50",
                Jobs::row, owner.issuer(), owner.subject()).stream().map(Job::view).toList();
    }

    View get(Owner owner, UUID id) {
        return owned(owner, id, false).view();
    }

    View approve(Owner owner, String bearer, UUID id, String code) {
        return transactions.execute(transaction -> {
            var job = owned(owner, id, true);
            var state = job.view().status();
            if ("SIGNING_QUEUED".equals(state) || "READY".equals(state)) return job.view();
            if (!"AWAITING_APPROVAL".equals(state)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Document is not awaiting approval");
            }
            peers.approve(bearer, job, code);
            db.update("""
                    UPDATE p7m_jobs SET status='SIGNING_QUEUED', attempts=0, next_attempt_at=now(),
                        expires_at=now()+interval '15 minutes' WHERE job_id=?
                    """, id);
            return owned(owner, id, false).view();
        });
    }

    Download download(Owner owner, UUID id) throws IOException {
        var job = owned(owner, id, false);
        if (!"READY".equals(job.view().status())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Signed file is not available");
        }
        var result = path(id, "p7m");
        long byteCount = Files.size(result);
        return new Download(job.filename() + ".p7m", Files.newInputStream(result), byteCount);
    }

    private Job owned(Owner owner, UUID id, boolean lock) {
        var jobs = db.query(OWNED + (lock ? " FOR UPDATE" : ""), Jobs::row, id, owner.issuer(), owner.subject());
        if (jobs.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Document operation not found");
        return jobs.getFirst();
    }

    @Scheduled(fixedDelay = 1000)
    void work() {
        transactions.executeWithoutResult(transaction -> {
            var jobs = db.query("SELECT " + COLUMNS + """
                    FROM p7m_jobs WHERE status IN ('QUEUED', 'SIGNING_QUEUED')
                    AND next_attempt_at <= now() AND expires_at > now()
                    ORDER BY next_attempt_at, created_at LIMIT 1 FOR UPDATE SKIP LOCKED
                    """, Jobs::row);
            if (jobs.isEmpty()) return;
            var job = jobs.getFirst();
            try {
                var source = path(job.id(), "source");
                if ("QUEUED".equals(job.status())) {
                    var digest = cades.prepare(source, job.certificate(), job.chain(), job.createdAt());
                    db.update("UPDATE p7m_jobs SET status='AWAITING_APPROVAL', digest=? WHERE job_id=?", digest, job.id());
                    return;
                }
                var partial = path(job.id(), "partial");
                cades.assemble(source, partial, job.certificate(), job.chain(), job.createdAt(), job.digest(), peers.sign(job));
                sync(partial);
                Files.move(partial, path(job.id(), "p7m"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                db.update("""
                        UPDATE p7m_jobs SET status='READY', ready_at=now(),
                            expires_at=now()+make_interval(hours => ?) WHERE job_id=?
                        """, retentionHours, job.id());
                // The cleanup task removes the source after READY commits.
            } catch (Exception error) {
                LOG.warn("Document job {} could not progress: {}", job.id(), error.getClass().getSimpleName());
                db.update("""
                        UPDATE p7m_jobs SET attempts=attempts+1, next_attempt_at=now()+interval '5 seconds',
                            status=CASE WHEN attempts>=2 THEN 'FAILED' ELSE status END WHERE job_id=?
                        """, job.id());
            }
        });
    }

    @Scheduled(fixedDelay = 1000)
    void cleanup() throws IOException {
        try (var files = Files.list(storage)) {
            for (var file : files.toList()) {
                var match = STORED_NAME.matcher(file.getFileName().toString());
                if (!match.matches()) continue;
                var id = UUID.fromString(match.group(1));
                boolean sourceOrPartial = !"p7m".equals(match.group(2));
                var states = db.query("SELECT status, expires_at <= now() AS expired FROM p7m_jobs WHERE job_id=?", (row, n) ->
                        row.getBoolean("expired") || sourceOrPartial && "READY".equals(row.getString("status")), id);
                boolean remove = states.isEmpty()
                        ? Files.getLastModifiedTime(file).toInstant().isBefore(Instant.now().minusSeconds(7200))
                        : states.getFirst();
                if (remove) Files.deleteIfExists(file);
            }
        }
    }

    private Path path(UUID id, String extension) {
        return storage.resolve(id + "." + extension);
    }

    private static void sync(Path file) throws IOException {
        try (var channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
    }

    private static Job row(ResultSet r, int row) throws SQLException {
        return new Job(r.getObject("job_id", UUID.class), r.getString("filename"), r.getString("key_id"),
                r.getString("credential_id"), r.getString("status"), r.getString("scheme"),
                r.getObject("created_at", OffsetDateTime.class).toInstant(),
                r.getObject("expires_at", OffsetDateTime.class).toInstant(),
                r.getString("certificate_pem"), r.getString("chain_pem"), r.getString("digest"));
    }
}
