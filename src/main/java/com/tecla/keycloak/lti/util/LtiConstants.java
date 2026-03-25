package com.tecla.keycloak.lti.util;

public final class LtiConstants {

    private LtiConstants() {}

    public static final String PROVIDER_ID = "lti-v13";
    public static final String PROVIDER_NAME = "LTI 1.3 (Blackboard)";

    // LTI claim base
    public static final String LTI_CLAIM_PREFIX = "https://purl.imsglobal.org/spec/lti/claim/";

    // LTI claims
    public static final String CLAIM_MESSAGE_TYPE = LTI_CLAIM_PREFIX + "message_type";
    public static final String CLAIM_VERSION = LTI_CLAIM_PREFIX + "version";
    public static final String CLAIM_DEPLOYMENT_ID = LTI_CLAIM_PREFIX + "deployment_id";
    public static final String CLAIM_TARGET_LINK_URI = LTI_CLAIM_PREFIX + "target_link_uri";
    public static final String CLAIM_RESOURCE_LINK = LTI_CLAIM_PREFIX + "resource_link";
    public static final String CLAIM_ROLES = LTI_CLAIM_PREFIX + "roles";
    public static final String CLAIM_CONTEXT = LTI_CLAIM_PREFIX + "context";
    public static final String CLAIM_CUSTOM = LTI_CLAIM_PREFIX + "custom";

    // Expected claim values
    public static final String LTI_VERSION = "1.3.0";
    public static final String MESSAGE_TYPE_RESOURCE_LINK = "LtiResourceLinkRequest";

    // LTI role URIs
    public static final String ROLE_LEARNER = "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner";
    public static final String ROLE_INSTRUCTOR = "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor";
    public static final String ROLE_ADMIN = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator";
    public static final String ROLE_CONTENT_DEVELOPER = "http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper";
    public static final String ROLE_MENTOR = "http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor";

    // Auth session note keys
    public static final String NOTE_NONCE = "lti_nonce";
    public static final String NOTE_LOGIN_HINT = "lti_login_hint";
    public static final String NOTE_LTI_MESSAGE_HINT = "lti_message_hint";
    public static final String NOTE_TARGET_LINK_URI = "lti_target_link_uri";

    // Context data keys (stored in BrokeredIdentityContext)
    public static final String CONTEXT_KEY_ROLES = "lti.roles";
    public static final String CONTEXT_KEY_CONTEXT = "lti.context";
}
