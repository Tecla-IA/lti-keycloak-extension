# LTI 1.3 Keycloak Extension

A Keycloak identity provider extension that enables LTI 1.3 authentication, allowing users from LTI platforms (e.g., Blackboard) to seamlessly authenticate into Keycloak-protected applications.

## Overview

This extension implements the [IMS Global LTI 1.3](https://www.imsglobal.org/spec/lti/v1p3/) specification as a Keycloak identity provider. When a user launches a tool from an LTI platform, the extension handles the OpenID Connect-based authentication flow, validates the platform's JWT, and creates or links a Keycloak user with the appropriate roles.

### Authentication Flow

```
LTI Platform (e.g., Blackboard)
  │
  ├─ 1. POST /realms/{realm}/lti-login   (login initiation)
  │
  ├─ 2. Redirect to Keycloak OIDC auth    (broker flow triggered)
  │
  ├─ 3. Redirect to platform auth URL     (id_token request via form_post)
  │
  ├─ 4. Platform authenticates user and POSTs id_token back
  │
  ├─ 5. JWT validated (signature, issuer, audience, nonce, expiry)
  │
  ├─ 6. User created/linked, LTI roles mapped to Keycloak roles
  │
  └─ 7. Redirect to target application
```

## Requirements

- **Java** 17+
- **Keycloak** 25.0.2+
- **Maven** 3.8+

## Build

```bash
mvn clean package
```

The JAR is produced at `target/lti-keycloak-extension-1.0.0-SNAPSHOT.jar`.

## Installation

Copy the built JAR into Keycloak's `providers` directory:

```bash
cp target/lti-keycloak-extension-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/
```

Then rebuild Keycloak (if running in production mode):

```bash
/opt/keycloak/bin/kc.sh build
```

Restart Keycloak for the extension to load.

## Configuration

### Identity Provider Setup

In the Keycloak Admin Console, navigate to **Identity Providers** and add a new **LTI 1.3 (Blackboard)** provider. Configure the following:

| Property | Required | Description |
|---|---|---|
| `platformIssuer` | Yes | LTI platform's issuer identifier (e.g., `https://blackboard.com`) |
| `clientId` | Yes | Client ID registered with the LTI platform |
| `jwksUrl` | Yes | Platform's JWKS endpoint for JWT signature verification |
| `authorizationUrl` | Yes | Platform's OIDC authorization endpoint |
| `deploymentId` | No | Deployment ID for the tool registration |
| `keycloakClientId` | Yes | Keycloak client ID used in the broker authentication flow |
| `defaultTargetUrl` | No | Default redirect URL after authentication (e.g., your SPA URL) |
| `emailDomain` | No | Fallback domain for generated emails when the platform doesn't provide one |
| `emailTag` | No | Institution tag for plus-address emails (e.g., `uvm` produces `user+uvm@domain.com`) |

### Role Mapping

The extension includes an **LTI Role Mapper** that maps LTI platform roles to Keycloak realm roles. Add it under the identity provider's mapper configuration:

- **LTI Role**: The LTI role URI to match (e.g., `http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor`)
- **Keycloak Role**: The target Keycloak realm role to assign

Roles are synchronized on every login -- if a user's LTI role is removed on the platform side, the corresponding Keycloak role is revoked.

### LTI Platform Registration

Register the following URLs with your LTI platform:

| URL | Purpose |
|---|---|
| `https://<keycloak-host>/realms/<realm>/lti-login` | Login initiation URL (OIDC launch) |
| `https://<keycloak-host>/realms/<realm>/broker/lti-v13/endpoint` | Redirect / callback URL |

## Project Structure

```
src/main/java/com/tecla/keycloak/lti/
├── endpoint/       # REST endpoint for LTI login initiation
├── mapper/         # LTI role-to-Keycloak role mapper
├── provider/       # Identity provider, config, and factory
└── util/           # JWT validation, nonce store, constants
```

## Security

- **JWT signature verification** via RS256 with JWKS (cached for 1 hour)
- **Nonce-based replay attack prevention** -- each nonce is single-use
- **Issuer and audience validation** on every token
- **Expiration checks** to reject stale tokens
- **Secure cookie storage** for LTI launch parameters (httpOnly, secure, 5-minute TTL)

## License

This project is licensed under the [MIT License](LICENSE).
