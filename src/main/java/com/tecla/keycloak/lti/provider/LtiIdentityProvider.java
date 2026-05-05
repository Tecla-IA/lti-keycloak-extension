package com.tecla.keycloak.lti.provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tecla.keycloak.lti.util.LtiConstants;
import com.tecla.keycloak.lti.util.LtiJwtValidator;
import com.tecla.keycloak.lti.util.LtiJwtValidator.LtiJwtValidationException;
import com.tecla.keycloak.lti.util.LtiNonceStore;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class LtiIdentityProvider extends AbstractIdentityProvider<LtiIdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(LtiIdentityProvider.class);
    private static final String LTI_PARAMS_COOKIE = "KC_LTI_PARAMS";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private final LtiJwtValidator jwtValidator;

    public LtiIdentityProvider(KeycloakSession session, LtiIdentityProviderConfig config) {
        super(session, config);
        this.jwtValidator = new LtiJwtValidator(
                config.getJwksUrl(),
                config.getPlatformIssuer(),
                config.getClientId()
        );
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            AuthenticationSessionModel authSession = request.getAuthenticationSession();
            String nonce = LtiNonceStore.generateAndStore(authSession);

            String redirectUri = request.getRedirectUri();
            String state = request.getState().getEncoded();

            // Read LTI params from cookie set by the initiation endpoint
            String loginHint = null;
            String ltiMessageHint = null;

            Map<String, Cookie> cookies = session.getContext().getRequestHeaders().getCookies();
            Cookie ltiCookie = cookies.get(LTI_PARAMS_COOKIE);
            if (ltiCookie != null) {
                try {
                    String json = new String(Base64.getUrlDecoder().decode(ltiCookie.getValue()), StandardCharsets.UTF_8);
                    JsonNode params = objectMapper.readTree(json);
                    if (params.has("lh")) {
                        loginHint = params.get("lh").asText();
                        authSession.setAuthNote(LtiConstants.NOTE_LOGIN_HINT, loginHint);
                    }
                    if (params.has("mh")) {
                        ltiMessageHint = params.get("mh").asText();
                        authSession.setAuthNote(LtiConstants.NOTE_LTI_MESSAGE_HINT, ltiMessageHint);
                    }
                    if (params.has("tl")) {
                        authSession.setAuthNote(LtiConstants.NOTE_TARGET_LINK_URI, params.get("tl").asText());
                    }
                } catch (Exception e) {
                    logger.warn("Failed to parse LTI params cookie", e);
                }
            }

            UriBuilder authUrl = UriBuilder.fromUri(getConfig().getAuthorizationUrl())
                    .queryParam("response_type", "id_token")
                    .queryParam("response_mode", "form_post")
                    .queryParam("scope", "openid")
                    .queryParam("client_id", getConfig().getClientId())
                    .queryParam("redirect_uri", redirectUri)
                    .queryParam("state", state)
                    .queryParam("nonce", nonce)
                    .queryParam("prompt", "none");

            if (loginHint != null) {
                authUrl.queryParam("login_hint", loginHint);
            }
            if (ltiMessageHint != null) {
                authUrl.queryParam("lti_message_hint", ltiMessageHint);
            }

            return Response.seeOther(authUrl.build()).build();

        } catch (Exception e) {
            logger.error("LTI login initiation failed", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("LTI login failed")
                    .build();
        }
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        // LTI 1.3 has no token endpoint — id_token comes directly via form_post
        return Response.ok().build();
    }

    @Override
    public Object callback(RealmModel realm, UserAuthenticationIdentityProvider.AuthenticationCallback callback, EventBuilder event) {
        return new LtiEndpoint(realm, callback, event, jwtValidator, getConfig(), LtiIdentityProvider.this);
    }

    public static class LtiEndpoint {

        private final RealmModel realm;
        private final UserAuthenticationIdentityProvider.AuthenticationCallback callback;
        private final EventBuilder event;
        private final LtiJwtValidator jwtValidator;
        private final LtiIdentityProviderConfig config;
        private final LtiIdentityProvider provider;

        public LtiEndpoint(RealmModel realm, UserAuthenticationIdentityProvider.AuthenticationCallback callback, EventBuilder event,
                           LtiJwtValidator jwtValidator, LtiIdentityProviderConfig config, LtiIdentityProvider provider) {
            this.realm = realm;
            this.callback = callback;
            this.event = event;
            this.jwtValidator = jwtValidator;
            this.config = config;
            this.provider = provider;
        }

        @POST
        @Path("")
        public Response handleCallbackPost(@FormParam("id_token") String idToken, @FormParam("state") String state) {
            logger.infof("LTI broker callback (POST): has_id_token=%s, has_state=%s",
                    idToken != null && !idToken.isBlank(), state != null && !state.isBlank());
            return handleCallback(idToken, state);
        }

        @GET
        @Path("")
        public Response handleCallbackGet(@QueryParam("id_token") String idToken, @QueryParam("state") String state) {
            logger.warnf("LTI broker callback received via GET — platform did not honor response_mode=form_post. has_id_token=%s, has_state=%s",
                    idToken != null && !idToken.isBlank(), state != null && !state.isBlank());
            return handleCallback(idToken, state);
        }

        private Response handleCallback(String idToken, String state) {
            try {
                if (idToken == null || idToken.isBlank()) {
                    logger.error("LTI callback: missing id_token");
                    return errorResponse("Missing id_token");
                }
                if (state == null || state.isBlank()) {
                    logger.error("LTI callback: missing state");
                    return errorResponse("Missing state");
                }

                // Resolve the auth session from state
                AuthenticationSessionModel authSession = callback.getAndVerifyAuthenticationSession(state);
                if (authSession == null) {
                    logger.error("LTI callback: invalid or expired state");
                    return errorResponse("Invalid or expired state");
                }

                // Get stored nonce
                String expectedNonce = authSession.getAuthNote(LtiConstants.NOTE_NONCE);

                // Validate JWT
                JsonNode payload = jwtValidator.validateAndParse(idToken, expectedNonce);
                logger.debugf("LTI JWT payload from platform: %s", payload.toPrettyString());

                // Consume the nonce
                LtiNonceStore.validateAndConsume(authSession, payload.get("nonce").asText());

                // Build brokered identity context
                BrokeredIdentityContext identity = buildIdentityContext(payload);
                identity.setIdp(provider);
                identity.setAuthenticationSession(authSession);

                return callback.authenticated(identity);

            } catch (LtiJwtValidationException e) {
                logger.errorf("LTI JWT validation failed: %s", e.getMessage());
                return errorResponse("JWT validation failed: " + e.getMessage());
            } catch (Exception e) {
                logger.error("LTI callback processing failed", e);
                return errorResponse("Authentication failed");
            }
        }

        private BrokeredIdentityContext buildIdentityContext(JsonNode payload) {
            String sub = payload.get("sub").asText();
            String iss = payload.get("iss").asText();

            // Composite broker user ID to prevent collisions across platforms
            String brokerUserId = iss + "|" + sub;

            BrokeredIdentityContext context = new BrokeredIdentityContext(brokerUserId, config);
            context.setUsername(sub);
            context.setModelUsername(sub);

            // Extract email, with fallback generation if configured
            JsonNode emailNode = payload.get("email");
            if (emailNode != null && !emailNode.isNull()) {
                context.setEmail(emailNode.asText());
            } else {
                String emailDomain = config.getEmailDomain();
                String emailTag = config.getEmailTag();
                if (emailDomain != null && !emailDomain.isBlank()) {
                    // Build local part from first+last name if available, otherwise fall back to sub
                    String localPart;
                    JsonNode givenNode = payload.get("given_name");
                    JsonNode familyNode = payload.get("family_name");
                    if (givenNode != null && !givenNode.isNull() && familyNode != null && !familyNode.isNull()) {
                        localPart = (givenNode.asText().trim() + "." + familyNode.asText().trim())
                                .toLowerCase().replaceAll("\\s+", "");
                    } else {
                        localPart = sub;
                    }

                    String generatedEmail;
                    if (emailTag != null && !emailTag.isBlank()) {
                        generatedEmail = localPart + "+" + emailTag + "@" + emailDomain;
                    } else {
                        generatedEmail = localPart + "@" + emailDomain;
                    }
                    context.setEmail(generatedEmail);
                    logger.infof("Generated fallback email for LTI user %s: %s", sub, generatedEmail);
                }
            }

            // Extract name
            JsonNode givenNameNode = payload.get("given_name");
            if (givenNameNode != null && !givenNameNode.isNull()) {
                context.setFirstName(givenNameNode.asText());
            }
            JsonNode familyNameNode = payload.get("family_name");
            if (familyNameNode != null && !familyNameNode.isNull()) {
                context.setLastName(familyNameNode.asText());
            }

            // If no given/family name, try "name" claim
            if (context.getFirstName() == null && context.getLastName() == null) {
                JsonNode nameNode = payload.get("name");
                if (nameNode != null && !nameNode.isNull()) {
                    String fullName = nameNode.asText();
                    int spaceIdx = fullName.indexOf(' ');
                    if (spaceIdx > 0) {
                        context.setFirstName(fullName.substring(0, spaceIdx));
                        context.setLastName(fullName.substring(spaceIdx + 1));
                    } else {
                        context.setFirstName(fullName);
                    }
                }
            }

            // Store LTI roles in context data for mappers
            JsonNode rolesNode = payload.get(LtiConstants.CLAIM_ROLES);
            if (rolesNode != null && rolesNode.isArray()) {
                List<String> roles = new ArrayList<>();
                for (JsonNode role : rolesNode) {
                    roles.add(role.asText());
                }
                context.getContextData().put(LtiConstants.CONTEXT_KEY_ROLES, roles);
            }

            // Store LTI context in context data for mappers
            JsonNode contextNode = payload.get(LtiConstants.CLAIM_CONTEXT);
            if (contextNode != null && !contextNode.isNull()) {
                context.getContextData().put(LtiConstants.CONTEXT_KEY_CONTEXT, contextNode.toString());
            }

            return context;
        }

        private Response errorResponse(String message) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .type(MediaType.TEXT_PLAIN)
                    .entity(message)
                    .build();
        }
    }
}
