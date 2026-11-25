package io.github.ziccardi.signbird.documents;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

final class CadesTest {
    @TempDir Path directory;

    @ParameterizedTest
    @ValueSource(strings = { "RSA", "EC" })
    void embedsOriginalAndVerifiesExternalSignature(String keyType) throws Exception {
        var keyGenerator = KeyPairGenerator.getInstance(keyType);
        if ("RSA".equals(keyType)) keyGenerator.initialize(2048);
        else keyGenerator.initialize(new ECGenParameterSpec("secp521r1"));
        var key = keyGenerator.generateKeyPair();
        String algorithm = "RSA".equals(keyType) ? "RSA" : "ECDSA";
        var issuer = new X500Name("CN=SignBird Test");
        var now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(issuer, BigInteger.ONE, Date.from(now.minusSeconds(60)),
                Date.from(now.plusSeconds(3600)), issuer, key.getPublic());
        var certificate = builder.build(new JcaContentSignerBuilder("SHA256with" + algorithm).build(key.getPrivate()));
        var pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----";
        var content = new byte[] { 0, 1, 2, (byte) 255, 10, 13 };
        var original = Files.write(directory.resolve("data"), content);
        var signed = directory.resolve("data.p7m");
        var cades = new Cades();
        String digest = cades.prepare(original, pem, pem, now);

        var signer = Signature.getInstance("NONEwith" + algorithm);
        signer.initSign(key.getPrivate());
        var digestBytes = Base64.getDecoder().decode(digest);
        if ("RSA".equals(keyType)) {
            var sha256 = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                    org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256,
                    org.bouncycastle.asn1.DERNull.INSTANCE);
            signer.update(new org.bouncycastle.asn1.x509.DigestInfo(sha256, digestBytes).getEncoded());
        } else {
            signer.update(digestBytes);
        }
        String signature = Base64.getEncoder().encodeToString(signer.sign());
        cades.assemble(original, signed, pem, pem, now, digest, signature);
        var result = new CMSSignedData(Files.readAllBytes(signed));
        assertArrayEquals(content, (byte[]) result.getSignedContent().getContent());
        var signerInfo = result.getSignerInfos().getSigners().iterator().next();
        assertTrue(signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificate)));

        Files.write(original, new byte[] { 7 });
        assertThrows(GeneralSecurityException.class,
                () -> cades.assemble(original, signed, pem, pem, now, digest, signature));
    }
}
