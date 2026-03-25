package com.tecla.keycloak.lti.util;

import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.UUID;

public final class LtiNonceStore {

    private LtiNonceStore() {}

    public static String generateAndStore(AuthenticationSessionModel authSession) {
        String nonce = UUID.randomUUID().toString();
        authSession.setAuthNote(LtiConstants.NOTE_NONCE, nonce);
        return nonce;
    }

    public static boolean validateAndConsume(AuthenticationSessionModel authSession, String nonce) {
        if (nonce == null || nonce.isBlank()) {
            return false;
        }
        String storedNonce = authSession.getAuthNote(LtiConstants.NOTE_NONCE);
        if (nonce.equals(storedNonce)) {
            authSession.removeAuthNote(LtiConstants.NOTE_NONCE);
            return true;
        }
        return false;
    }
}
