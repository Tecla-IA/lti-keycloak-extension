package com.tecla.keycloak.lti.mapper;

import com.fasterxml.jackson.databind.JsonNode;
import com.tecla.keycloak.lti.util.LtiConstants;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.util.JsonSerialization;

import java.util.Collections;
import java.util.List;

public class LtiAttributeMapper extends AbstractIdentityProviderMapper {

    private static final Logger logger = Logger.getLogger(LtiAttributeMapper.class);

    public static final String PROVIDER_ID = "lti-attribute-mapper";
    private static final String CONFIG_LTI_CLAIM = "ltiClaim";
    private static final String CONFIG_USER_ATTRIBUTE = "userAttribute";

    private static final String[] COMPATIBLE_PROVIDERS = { LtiConstants.PROVIDER_ID };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return "Attribute Mapper";
    }

    @Override
    public String getDisplayType() {
        return "LTI Claim to User Attribute";
    }

    @Override
    public String getHelpText() {
        return "Maps an LTI claim value to a Keycloak user attribute.";
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                    .name(CONFIG_LTI_CLAIM)
                    .label("LTI Claim Path")
                    .helpText("The LTI claim to extract (e.g., 'https://purl.imsglobal.org/spec/lti/claim/context.label' or a simple path like 'context.label')")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(CONFIG_USER_ATTRIBUTE)
                    .label("User Attribute")
                    .helpText("The Keycloak user attribute name to set")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .build();
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm,
                              UserModel user, IdentityProviderMapperModel mapperModel,
                              BrokeredIdentityContext context) {
        applyAttribute(user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm,
                                   UserModel user, IdentityProviderMapperModel mapperModel,
                                   BrokeredIdentityContext context) {
        applyAttribute(user, mapperModel, context);
    }

    private void applyAttribute(UserModel user, IdentityProviderMapperModel mapperModel,
                                BrokeredIdentityContext context) {
        String claimPath = mapperModel.getConfig().get(CONFIG_LTI_CLAIM);
        String userAttribute = mapperModel.getConfig().get(CONFIG_USER_ATTRIBUTE);

        if (claimPath == null || userAttribute == null) {
            return;
        }

        String value = extractClaimValue(claimPath, context);
        if (value != null) {
            user.setAttribute(userAttribute, Collections.singletonList(value));
            logger.debugf("Set user attribute '%s' = '%s' from LTI claim '%s'",
                    userAttribute, value, claimPath);
        }
    }

    private String extractClaimValue(String claimPath, BrokeredIdentityContext context) {
        // Try extracting from the LTI context data (stored as JSON string)
        String contextJson = (String) context.getContextData().get(LtiConstants.CONTEXT_KEY_CONTEXT);
        if (contextJson == null) {
            return null;
        }

        try {
            JsonNode contextNode = JsonSerialization.readValue(contextJson, JsonNode.class);

            // Support dotted path traversal (e.g., "context.label" or just "label")
            // Strip the LTI claim prefix if present
            String path = claimPath;
            if (path.startsWith(LtiConstants.LTI_CLAIM_PREFIX)) {
                path = path.substring(LtiConstants.LTI_CLAIM_PREFIX.length());
            }
            // Remove leading "context." since we're already in the context node
            if (path.startsWith("context.")) {
                path = path.substring("context.".length());
            }

            String[] parts = path.split("\\.");
            JsonNode current = contextNode;
            for (String part : parts) {
                if (current == null || current.isNull()) {
                    return null;
                }
                current = current.get(part);
            }

            if (current != null && !current.isNull()) {
                return current.isTextual() ? current.asText() : current.toString();
            }
        } catch (Exception e) {
            logger.warnf("Failed to extract LTI claim '%s': %s", claimPath, e.getMessage());
        }

        return null;
    }
}
