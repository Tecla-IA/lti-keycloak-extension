package com.tecla.keycloak.lti.util;

import org.jboss.logging.Logger;
import org.keycloak.crypto.Algorithm;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.databind.JsonNode;

public class LtiJwtValidator {

    private static final Logger logger = Logger.getLogger(LtiJwtValidator.class);
    private static final long JWKS_CACHE_TTL_MS = 3600_000; // 1 hour
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private final String jwksUrl;
    private final String expectedIssuer;
    private final String expectedClientId;

    // JWKS cache: kid -> PublicKey
    private final ConcurrentHashMap<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private volatile long lastFetchTime = 0;

    public LtiJwtValidator(String jwksUrl, String expectedIssuer, String expectedClientId) {
        this.jwksUrl = jwksUrl;
        this.expectedIssuer = expectedIssuer;
        this.expectedClientId = expectedClientId;
    }

    public JsonNode validateAndParse(String idToken, String expectedNonce) throws LtiJwtValidationException {
        try {
            JWSInput jws = new JWSInput(idToken);
            String kid = jws.getHeader().getKeyId();
            String algorithm = jws.getHeader().getAlgorithm().name();

            if (!Algorithm.RS256.equals(algorithm)) {
                throw new LtiJwtValidationException("Unsupported algorithm: " + algorithm);
            }

            // Verify signature
            PublicKey publicKey = getPublicKey(kid);
            if (publicKey == null) {
                throw new LtiJwtValidationException("No public key found for kid: " + kid);
            }

            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(jws.getEncodedSignatureInput().getBytes("UTF-8"));
            if (!verifier.verify(jws.getSignature())) {
                throw new LtiJwtValidationException("JWT signature verification failed");
            }

            // Parse payload
            JsonNode payload = JsonSerialization.readValue(jws.getContent(), JsonNode.class);

            // Validate standard claims
            validateIssuer(payload);
            validateAudience(payload);
            validateExpiration(payload);
            validateIssuedAt(payload);
            validateNonce(payload, expectedNonce);

            // Validate LTI-specific claims
            validateLtiVersion(payload);
            validateMessageType(payload);

            return payload;

        } catch (JWSInputException e) {
            throw new LtiJwtValidationException("Failed to parse JWT", e);
        } catch (LtiJwtValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new LtiJwtValidationException("JWT validation failed", e);
        }
    }

    private void validateIssuer(JsonNode payload) throws LtiJwtValidationException {
        String iss = getTextClaim(payload, "iss");
        if (!expectedIssuer.equals(iss)) {
            throw new LtiJwtValidationException("Invalid issuer: expected " + expectedIssuer + ", got " + iss);
        }
    }

    private void validateAudience(JsonNode payload) throws LtiJwtValidationException {
        JsonNode audNode = payload.get("aud");
        if (audNode == null) {
            throw new LtiJwtValidationException("Missing aud claim");
        }
        boolean audienceMatch;
        if (audNode.isArray()) {
            audienceMatch = false;
            for (JsonNode aud : audNode) {
                if (expectedClientId.equals(aud.asText())) {
                    audienceMatch = true;
                    break;
                }
            }
        } else {
            audienceMatch = expectedClientId.equals(audNode.asText());
        }
        if (!audienceMatch) {
            throw new LtiJwtValidationException("Client ID not found in aud claim");
        }
    }

    private void validateExpiration(JsonNode payload) throws LtiJwtValidationException {
        JsonNode expNode = payload.get("exp");
        if (expNode == null) {
            throw new LtiJwtValidationException("Missing exp claim");
        }
        long exp = expNode.asLong();
        long now = System.currentTimeMillis() / 1000;
        if (now > exp) {
            throw new LtiJwtValidationException("Token has expired");
        }
    }

    private void validateIssuedAt(JsonNode payload) throws LtiJwtValidationException {
        JsonNode iatNode = payload.get("iat");
        if (iatNode == null) {
            throw new LtiJwtValidationException("Missing iat claim");
        }
    }

    private void validateNonce(JsonNode payload, String expectedNonce) throws LtiJwtValidationException {
        String nonce = getTextClaim(payload, "nonce");
        if (nonce == null || !nonce.equals(expectedNonce)) {
            throw new LtiJwtValidationException("Nonce mismatch");
        }
    }

    private void validateLtiVersion(JsonNode payload) throws LtiJwtValidationException {
        String version = getTextClaim(payload, LtiConstants.CLAIM_VERSION);
        if (!LtiConstants.LTI_VERSION.equals(version)) {
            throw new LtiJwtValidationException("Invalid LTI version: " + version);
        }
    }

    private void validateMessageType(JsonNode payload) throws LtiJwtValidationException {
        String messageType = getTextClaim(payload, LtiConstants.CLAIM_MESSAGE_TYPE);
        if (!LtiConstants.MESSAGE_TYPE_RESOURCE_LINK.equals(messageType)) {
            throw new LtiJwtValidationException("Invalid message type: " + messageType);
        }
    }

    private String getTextClaim(JsonNode payload, String claim) {
        JsonNode node = payload.get(claim);
        return (node != null && !node.isNull()) ? node.asText() : null;
    }

    private PublicKey getPublicKey(String kid) throws LtiJwtValidationException {
        PublicKey cached = keyCache.get(kid);
        if (cached != null && !isCacheExpired()) {
            return cached;
        }

        synchronized (this) {
            // Double-check after acquiring lock
            cached = keyCache.get(kid);
            if (cached != null && !isCacheExpired()) {
                return cached;
            }
            refreshJwks();
        }

        return keyCache.get(kid);
    }

    private boolean isCacheExpired() {
        return (System.currentTimeMillis() - lastFetchTime) > JWKS_CACHE_TTL_MS;
    }

    private void refreshJwks() throws LtiJwtValidationException {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(jwksUrl))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new LtiJwtValidationException("JWKS fetch failed with status: " + response.statusCode());
            }

            JSONWebKeySet jwks = JsonSerialization.readValue(response.body(), JSONWebKeySet.class);
            keyCache.clear();
            for (JWK jwk : jwks.getKeys()) {
                if (jwk.getKeyId() != null) {
                    PublicKey pk = JWKParser.create(jwk).toPublicKey();
                    keyCache.put(jwk.getKeyId(), pk);
                }
            }
            lastFetchTime = System.currentTimeMillis();

            logger.debugf("Refreshed JWKS from %s, loaded %d keys", jwksUrl, keyCache.size());

        } catch (LtiJwtValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new LtiJwtValidationException("Failed to fetch JWKS from " + jwksUrl, e);
        }
    }

    public static class LtiJwtValidationException extends Exception {
        public LtiJwtValidationException(String message) {
            super(message);
        }

        public LtiJwtValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
