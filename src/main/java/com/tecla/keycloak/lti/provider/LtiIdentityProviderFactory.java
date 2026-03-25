package com.tecla.keycloak.lti.provider;

import com.tecla.keycloak.lti.util.LtiConstants;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class LtiIdentityProviderFactory extends AbstractIdentityProviderFactory<LtiIdentityProvider> {

    @Override
    public String getName() {
        return LtiConstants.PROVIDER_NAME;
    }

    @Override
    public String getId() {
        return LtiConstants.PROVIDER_ID;
    }

    @Override
    public LtiIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new LtiIdentityProvider(session, new LtiIdentityProviderConfig(model));
    }

    @Override
    public LtiIdentityProviderConfig createConfig() {
        return new LtiIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                    .name("platformIssuer")
                    .label("Platform Issuer")
                    .helpText("The issuer identifier for the LTI platform (e.g., https://blackboard.com)")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name("clientId")
                    .label("Client ID")
                    .helpText("The client_id registered with the LTI platform")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name("jwksUrl")
                    .label("JWKS URL")
                    .helpText("URL to the platform's JSON Web Key Set for JWT signature verification")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name("authorizationUrl")
                    .label("Authorization URL")
                    .helpText("The platform's OIDC authorization endpoint")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name("deploymentId")
                    .label("Deployment ID")
                    .helpText("The deployment_id for this tool registration")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name("keycloakClientId")
                    .label("Keycloak Client ID")
                    .helpText("The Keycloak client_id used for the broker authentication flow (e.g., your SPA client)")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name("defaultTargetUrl")
                    .label("Default Target URL")
                    .helpText("Default redirect URL after successful authentication (e.g., your SPA URL)")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name("emailDomain")
                    .label("Fallback Email Domain")
                    .helpText("Domain for generated emails when the platform doesn't provide one (e.g., teclaacademy.com)")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name("emailTag")
                    .label("Fallback Email Tag")
                    .helpText("Institution tag inserted as plus-address in generated emails (e.g., uvm → user+uvm@domain.com)")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .build();
    }
}
