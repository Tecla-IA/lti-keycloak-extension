package com.tecla.keycloak.lti.endpoint;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class LtiLoginInitiationResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public LtiLoginInitiationResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new LtiLoginInitiationEndpoint(session);
    }

    @Override
    public void close() {
        // no-op
    }
}
