package signbird.documents;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

final class Cades {
    private final CAdESService service = new CAdESService(new CommonCertificateVerifier());

    private CAdESSignatureParameters parameters(String certificate, String chain, Instant signingTime)
            throws GeneralSecurityException {
        var factory = CertificateFactory.getInstance("X.509");
        var leaf = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(certificate.getBytes(StandardCharsets.US_ASCII)));
        var tokens = new ArrayList<CertificateToken>();
        var signer = new CertificateToken(leaf);
        tokens.add(signer);
        for (var item : factory.generateCertificates(new ByteArrayInputStream(chain.getBytes(StandardCharsets.US_ASCII)))) {
            if (!leaf.equals(item)) tokens.add(new CertificateToken((X509Certificate) item));
        }
        var parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(signer);
        parameters.setCertificateChain(tokens);
        parameters.bLevel().setSigningDate(Date.from(signingTime));
        return parameters;
    }

    String prepare(Path source, String certificate, String chain, Instant signingTime) throws GeneralSecurityException {
        var parameters = parameters(certificate, chain, signingTime);
        return digest(service.getDataToSign(new FileDocument(source.toFile()), parameters).getBytes());
    }

    void assemble(Path source, Path target, String certificate, String chain, Instant signingTime,
                  String approvedDigest, String signature) throws GeneralSecurityException, IOException {
        var parameters = parameters(certificate, chain, signingTime);
        var document = new FileDocument(source.toFile());
        var signedAttributes = service.getDataToSign(document, parameters).getBytes();
        if (!approvedDigest.equals(digest(signedAttributes))) {
            throw new GeneralSecurityException("Prepared document digest changed");
        }
        var signatureBytes = Base64.getDecoder().decode(signature);
        var publicKey = parameters.getSigningCertificate().getCertificate().getPublicKey();
        var verifier = Signature.getInstance("SHA256with" + ("EC".equals(publicKey.getAlgorithm()) ? "ECDSA" : "RSA"));
        verifier.initVerify(publicKey);
        verifier.update(signedAttributes);
        if (!verifier.verify(signatureBytes)) {
            throw new GeneralSecurityException("External signature does not match the approved digest");
        }
        var value = new SignatureValue(parameters.getSignatureAlgorithm(), signatureBytes);
        service.signDocument(document, parameters, value).save(target.toString());
    }

    private String digest(byte[] bytes) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
