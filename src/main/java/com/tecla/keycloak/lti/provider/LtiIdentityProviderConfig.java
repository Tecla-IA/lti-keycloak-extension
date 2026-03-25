package com.tecla.keycloak.lti.provider;

import org.keycloak.models.IdentityProviderModel;

public class LtiIdentityProviderConfig extends IdentityProviderModel {

    private static final String PLATFORM_ISSUER = "platformIssuer";
    private static final String CLIENT_ID = "clientId";
    private static final String JWKS_URL = "jwksUrl";
    private static final String AUTHORIZATION_URL = "authorizationUrl";
    private static final String DEPLOYMENT_ID = "deploymentId";
    private static final String DEFAULT_TARGET_URL = "defaultTargetUrl";
    private static final String KEYCLOAK_CLIENT_ID = "keycloakClientId";
    private static final String EMAIL_DOMAIN = "emailDomain";
    private static final String EMAIL_TAG = "emailTag";

    public LtiIdentityProviderConfig() {
        super();
    }

    public LtiIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public String getPlatformIssuer() {
        return getConfig().get(PLATFORM_ISSUER);
    }

    public void setPlatformIssuer(String issuer) {
        getConfig().put(PLATFORM_ISSUER, issuer);
    }

    public String getClientId() {
        return getConfig().get(CLIENT_ID);
    }

    public void setClientId(String clientId) {
        getConfig().put(CLIENT_ID, clientId);
    }

    public String getJwksUrl() {
        return getConfig().get(JWKS_URL);
    }

    public void setJwksUrl(String jwksUrl) {
        getConfig().put(JWKS_URL, jwksUrl);
    }

    public String getAuthorizationUrl() {
        return getConfig().get(AUTHORIZATION_URL);
    }

    public void setAuthorizationUrl(String authorizationUrl) {
        getConfig().put(AUTHORIZATION_URL, authorizationUrl);
    }

    public String getDeploymentId() {
        return getConfig().get(DEPLOYMENT_ID);
    }

    public void setDeploymentId(String deploymentId) {
        getConfig().put(DEPLOYMENT_ID, deploymentId);
    }

    public String getDefaultTargetUrl() {
        return getConfig().get(DEFAULT_TARGET_URL);
    }

    public void setDefaultTargetUrl(String defaultTargetUrl) {
        getConfig().put(DEFAULT_TARGET_URL, defaultTargetUrl);
    }

    public String getKeycloakClientId() {
        return getConfig().get(KEYCLOAK_CLIENT_ID);
    }

    public void setKeycloakClientId(String keycloakClientId) {
        getConfig().put(KEYCLOAK_CLIENT_ID, keycloakClientId);
    }

    public String getEmailDomain() {
        return getConfig().get(EMAIL_DOMAIN);
    }

    public void setEmailDomain(String emailDomain) {
        getConfig().put(EMAIL_DOMAIN, emailDomain);
    }

    public String getEmailTag() {
        return getConfig().get(EMAIL_TAG);
    }

    public void setEmailTag(String emailTag) {
        getConfig().put(EMAIL_TAG, emailTag);
    }
}
