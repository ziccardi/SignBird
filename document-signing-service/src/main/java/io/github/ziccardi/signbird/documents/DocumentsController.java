package io.github.ziccardi.signbird.documents;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

@RestController
final class DocumentsController {
    record Approval(String code) {}
    private final Jobs jobs;
    private final byte[] gatewayToken;

    DocumentsController(Jobs jobs, @Value("${SIGNBIRD_DOCUMENT_GATEWAY_TOKEN}") String gatewayToken) {
        if (gatewayToken.length() < 32) throw new IllegalArgumentException("Document gateway token is too short");
        this.jobs = jobs;
        this.gatewayToken = gatewayToken.getBytes(StandardCharsets.UTF_8);
    }

    @GetMapping("/healthz")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void health() {}

    @PostMapping(path="/v1/signatures/p7m", consumes=MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseStatus(HttpStatus.ACCEPTED)
    Jobs.View upload(HttpServletRequest request, @RequestParam String keyId, @RequestParam String credentialId,
                     @RequestParam MultipartFile file) throws IOException {
        if (!keyId.matches("[a-f0-9]{32}") || !credentialId.matches("[a-f0-9]{32}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid key or credential identifier");
        }
        return jobs.upload(owner(request), request.getHeader(HttpHeaders.AUTHORIZATION), keyId, credentialId, file);
    }

    @GetMapping("/v1/signatures/p7m")
    List<Jobs.View> list(HttpServletRequest request) {
        return jobs.list(owner(request));
    }

    @GetMapping("/v1/signatures/p7m/{jobId}")
    Jobs.View detail(HttpServletRequest request, @PathVariable UUID jobId) {
        return jobs.get(owner(request), jobId);
    }

    @PostMapping("/v1/signatures/p7m/{jobId}/approve")
    @ResponseStatus(HttpStatus.ACCEPTED)
    Jobs.View approve(HttpServletRequest request, @PathVariable UUID jobId, @RequestBody Approval approval) {
        if (approval.code() == null || !approval.code().matches("[0-9]{6}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "TOTP must contain six digits");
        }
        return jobs.approve(owner(request), request.getHeader(HttpHeaders.AUTHORIZATION), jobId, approval.code());
    }

    @GetMapping("/v1/signatures/p7m/{jobId}/download")
    ResponseEntity<InputStreamResource> download(HttpServletRequest request, @PathVariable UUID jobId) throws IOException {
        var file = jobs.download(owner(request), jobId);
        return ResponseEntity.ok().contentLength(file.byteCount()).contentType(MediaType.parseMediaType("application/pkcs7-mime"))
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(file.filename(), StandardCharsets.UTF_8).build().toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(new InputStreamResource(file.stream()));
    }

    private Jobs.Owner owner(HttpServletRequest request) {
        var supplied = request.getHeader("X-SignBird-Service-Token");
        if (supplied != null && MessageDigest.isEqual(gatewayToken, supplied.getBytes(StandardCharsets.UTF_8))) {
            try {
                var decoder = Base64.getUrlDecoder();
                var issuer = new String(decoder.decode(request.getHeader("X-SignBird-Owner-Issuer")), StandardCharsets.UTF_8);
                var subject = new String(decoder.decode(request.getHeader("X-SignBird-Owner-Subject")), StandardCharsets.UTF_8);
                if (!issuer.isBlank() && !subject.isBlank()) return new Jobs.Owner(issuer, subject);
            } catch (IllegalArgumentException | NullPointerException ignored) {
                // The gateway supplies both identity headers.
            }
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid gateway credentials");
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, String>> applicationError(ResponseStatusException error) {
        return ResponseEntity.status(error.getStatusCode()).body(Map.of("message", error.getReason()));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    ResponseEntity<Map<String, String>> sizeLimit() {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(Map.of("message", "The file exceeds the 10 MB limit"));
    }
}
