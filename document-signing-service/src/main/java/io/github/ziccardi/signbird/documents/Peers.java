package io.github.ziccardi.signbird.documents;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.server.ResponseStatusException;

@Component
final class Peers {
    record Credential(String certificate, String chain, String scheme) {}

    private final RestClient api;
    private final RestClient activation;

    Peers(@Value("${SIGNBIRD_DOCUMENT_SERVICE_TOKEN}") String token) {
        if (token.length() < 32) throw new IllegalArgumentException("Document service token is too short");
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        var factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(Duration.ofSeconds(15));
        api = RestClient.builder().baseUrl("http://127.0.0.1:8080").requestFactory(factory).build();
        activation = RestClient.builder().baseUrl("http://127.0.0.1:8082").requestFactory(factory)
                .defaultHeader("X-SignBird-Service-Token", token).build();
    }

    Credential credential(String bearer, String key, String credential) {
        try {
            var result = api.get().uri("/v1/keys/{key}", key)
                    .header("Authorization", bearer).retrieve().body(JsonNode.class);
            if (result != null && "ACTIVE".equals(result.path("status").asText())) {
                for (var cert : result.path("certificates")) {
                    if (credential.equals(cert.path("credentialId").asText())
                            && !Instant.now().isBefore(Instant.parse(cert.path("notBefore").asText()))
                            && Instant.now().isBefore(Instant.parse(cert.path("notAfter").asText()))) {
                        var algorithm = result.path("algorithm").asText();
                        var scheme = switch (algorithm) {
                            case "RSA-2048" -> "RSASSA-PKCS1-v1_5";
                            case "ECDSA-P256", "ECDSA-P521" -> "ECDSA";
                            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported key algorithm");
                        };
                        return new Credential(cert.path("certificatePem").asText(), cert.path("chainPem").asText(), scheme);
                    }
                }
            }
        } catch (RestClientResponseException error) {
            if (error.getStatusCode().value() != 404) throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Key service unavailable");
        }
        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Signing credential unavailable");
    }

    void approve(String bearer, Jobs.Job job, String code) {
        try {
            activation.post().uri("/internal/documents/{id}/approve", job.id()).header("Authorization", bearer)
                    .body(Map.of("keyId", job.key(), "credentialId", job.credential(), "digest", job.digest(),
                            "signatureScheme", job.scheme(), "code", code)).retrieve().toBodilessEntity();
        } catch (RestClientResponseException error) {
            int status = error.getStatusCode().value();
            String message = switch (status) {
                case 400 -> "Invalid or already used TOTP code";
                case 404 -> "Signing credential unavailable";
                case 409 -> "TOTP enrollment is required";
                case 429 -> "Too many attempts. Try again later";
                default -> "Activation service unavailable";
            };
            throw new ResponseStatusException(status == 400 || status == 404 || status == 409 || status == 429
                    ? error.getStatusCode() : HttpStatus.BAD_GATEWAY, message);
        }
    }

    String sign(Jobs.Job job) {
        var response = activation.post().uri("/internal/documents/{id}/sign", job.id()).retrieve().body(JsonNode.class);
        if (response == null || response.path("signature").asText().isEmpty()) throw new IllegalStateException("Missing signature");
        return response.path("signature").asText();
    }
}
