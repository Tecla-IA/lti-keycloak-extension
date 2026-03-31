package com.tecla.keycloak.lti.mapper;

import com.tecla.keycloak.lti.util.LtiConstants;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class LtiRoleMapper extends AbstractIdentityProviderMapper {

    private static final Logger logger = Logger.getLogger(LtiRoleMapper.class);

    public static final String PROVIDER_ID = "lti-role-mapper";
    private static final String CONFIG_LTI_ROLE = "ltiRole";
    private static final String CONFIG_KEYCLOAK_ROLE = "keycloakRole";

    private static final String[] COMPATIBLE_PROVIDERS = { LtiConstants.PROVIDER_ID };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return "Role Mapper";
    }

    @Override
    public String getDisplayType() {
        return "LTI Role to Keycloak Role";
    }

    @Override
    public String getHelpText() {
        return "Maps an LTI role URI to a Keycloak realm or client role.";
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                    .name(CONFIG_LTI_ROLE)
                    .label("LTI Role URI")
                    .helpText("The LTI role URI to match (e.g., http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor)")
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .add()
                .property()
                    .name(CONFIG_KEYCLOAK_ROLE)
                    .label("Keycloak Role")
                    .helpText("The Keycloak realm role to assign when the LTI role matches")
                    .type(ProviderConfigProperty.ROLE_TYPE)
                    .add()
                .build();
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm,
                              UserModel user, IdentityProviderMapperModel mapperModel,
                              BrokeredIdentityContext context) {
        applyRole(realm, user, mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm,
                                   UserModel user, IdentityProviderMapperModel mapperModel,
                                   BrokeredIdentityContext context) {
        applyRole(realm, user, mapperModel, context);
    }

    @SuppressWarnings("unchecked")
    private void applyRole(RealmModel realm, UserModel user,
                           IdentityProviderMapperModel mapperModel,
                           BrokeredIdentityContext context) {
        String targetLtiRole = mapperModel.getConfig().get(CONFIG_LTI_ROLE);
        String keycloakRoleName = mapperModel.getConfig().get(CONFIG_KEYCLOAK_ROLE);

        if (targetLtiRole == null || keycloakRoleName == null) {
            return;
        }

        List<String> ltiRoles = (List<String>) context.getContextData().get(LtiConstants.CONTEXT_KEY_ROLES);
        if (ltiRoles == null) {
            return;
        }

        RoleModel role = realm.getRole(keycloakRoleName);
        if (role == null) {
            logger.warnf("Keycloak role '%s' not found in realm '%s'", keycloakRoleName, realm.getName());
            return;
        }

        if (ltiRoles.contains(targetLtiRole)) {
            user.grantRole(role);
            logger.debugf("Granted role '%s' to user '%s' based on LTI role '%s'",
                    keycloakRoleName, user.getUsername(), targetLtiRole);
        } else {
            logger.debugf("LTI role '%s' not present for user '%s', skipping role '%s'",
                    targetLtiRole, user.getUsername(), keycloakRoleName);
        }
    }
}
