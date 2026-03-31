package com.tecla.keycloak.lti.endpoint;

import com.tecla.keycloak.lti.util.LtiConstants;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.net.URI;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class LtiLoginInitiationEndpoint {

    private static final Logger logger = Logger.getLogger(LtiLoginInitiationEndpoint.class);
    private static final String LTI_PARAMS_COOKIE = "KC_LTI_PARAMS";

    private final KeycloakSession session;
    private final RealmModel realm;

    public LtiLoginInitiationEndpoint(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response handleGet(
            @QueryParam("iss") String iss,
            @QueryParam("login_hint") String loginHint,
            @QueryParam("target_link_uri") String targetLinkUri,
            @QueryParam("lti_message_hint") String ltiMessageHint,
            @QueryParam("client_id") String clientId) {
        return processInitiation(iss, loginHint, targetLinkUri, ltiMessageHint, clientId);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response handlePost(
            @FormParam("iss") String iss,
            @FormParam("login_hint") String loginHint,
            @FormParam("target_link_uri") String targetLinkUri,
            @FormParam("lti_message_hint") String ltiMessageHint,
            @FormParam("client_id") String clientId) {
        return processInitiation(iss, loginHint, targetLinkUri, ltiMessageHint, clientId);
    }

    private Response processInitiation(String iss, String loginHint, String targetLinkUri,
                                       String ltiMessageHint, String clientId) {
        try {
            logger.infof("LTI login initiation: iss=%s, client_id=%s, target_link_uri=%s", iss, clientId, targetLinkUri);

            if (iss == null || iss.isBlank()) {
                return errorResponse("Missing required parameter: iss");
            }
            if (loginHint == null || loginHint.isBlank()) {
                return errorResponse("Missing required parameter: login_hint");
            }

            // Find the matching LTI IdP config
            IdentityProviderModel idpModel = findLtiProvider(iss, clientId);
            if (idpModel == null) {
                logger.errorf("No LTI IdP found for iss=%s, client_id=%s", iss, clientId);
                return errorResponse("No matching LTI identity provider configured");
            }

            String keycloakClientId = idpModel.getConfig().get("keycloakClientId");
            String defaultTargetUrl = idpModel.getConfig().get("defaultTargetUrl");

            if (keycloakClientId == null || keycloakClientId.isBlank()) {
                logger.error("LTI IdP config missing keycloakClientId");
                return errorResponse("LTI identity provider misconfigured: missing keycloakClientId");
            }

            // Determine redirect URI (where Keycloak sends user after auth)
            String redirectUri = (defaultTargetUrl != null && !defaultTargetUrl.isBlank())
                    ? defaultTargetUrl
                    : targetLinkUri;

            // Encode LTI params into a cookie so performLogin() can read them
            // Cookie path must include the base URI path (e.g. "/auth/") so it's
            // sent on subsequent requests under /auth/realms/{realm}/...
            String cookieValue = encodeLtiParams(loginHint, ltiMessageHint, targetLinkUri);
            String basePath = session.getContext().getUri().getBaseUri().getPath();
            NewCookie ltiCookie = new NewCookie.Builder(LTI_PARAMS_COOKIE)
                    .value(cookieValue)
                    .path(basePath + "realms/" + realm.getName())
                    .maxAge(300) // 5 min TTL
                    .secure(true)
                    .httpOnly(true)
                    .sameSite(NewCookie.SameSite.NONE) // LTI launches originate cross-site
                    .build();

            // Redirect to Keycloak's OIDC auth endpoint with kc_idp_hint to trigger the LTI broker flow
            URI authUri = UriBuilder.fromUri(session.getContext().getUri().getBaseUri())
                    .path("realms/{realm}/protocol/openid-connect/auth")
                    .resolveTemplate("realm", realm.getName())
                    .queryParam("client_id", keycloakClientId)
                    .queryParam("redirect_uri", redirectUri)
                    .queryParam("response_type", "code")
                    .queryParam("scope", "openid")
                    .queryParam("kc_idp_hint", idpModel.getAlias())
                    .build();

            logger.infof("LTI login initiation: redirecting through broker flow to %s", authUri);
            return Response.seeOther(authUri).cookie(ltiCookie).build();

        } catch (Exception e) {
            logger.error("LTI login initiation failed", e);
            return errorResponse("Login initiation failed: " + e.getMessage());
        }
    }

    /**
     * Encode LTI params as base64 JSON for cookie storage.
     */
    private String encodeLtiParams(String loginHint, String ltiMessageHint, String targetLinkUri) {
        // Simple JSON encoding without external dependencies
        StringBuilder json = new StringBuilder("{");
        json.append("\"lh\":\"").append(escapeJson(loginHint)).append("\"");
        if (ltiMessageHint != null) {
            json.append(",\"mh\":\"").append(escapeJson(ltiMessageHint)).append("\"");
        }
        if (targetLinkUri != null) {
            json.append(",\"tl\":\"").append(escapeJson(targetLinkUri)).append("\"");
        }
        json.append("}");
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.toString().getBytes(StandardCharsets.UTF_8));
    }

    private String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private IdentityProviderModel findLtiProvider(String iss, String clientId) {
        for (IdentityProviderModel idp : realm.getIdentityProvidersStream().toList()) {
            if (!LtiConstants.PROVIDER_ID.equals(idp.getProviderId())) {
                continue;
            }
            String configuredIssuer = idp.getConfig().get("platformIssuer");
            String configuredClientId = idp.getConfig().get("clientId");

            if (iss.equals(configuredIssuer)) {
                if (clientId != null && !clientId.isBlank() && !clientId.equals(configuredClientId)) {
                    continue;
                }
                return idp;
            }
        }
        return null;
    }

    private Response errorResponse(String message) {
        return Response.status(Response.Status.BAD_REQUEST)
                .type(MediaType.TEXT_PLAIN)
                .entity(message)
                .build();
    }
}
