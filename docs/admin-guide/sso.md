# Single Sign-On (SSO) Integration

Nebulae supports standard Single Sign-On (SSO) with **any OpenID Connect (OIDC)** or **Reverse Proxy ForwardAuth** provider, including:

* **Authelia**
* **Authentik**
* **Keycloak**
* **Okta / Auth0 / JumpCloud**
* **Google Workspace / Microsoft Entra ID (Azure AD)**
* **Zitadel / Kanidm**
* **Cloudflare Access / Tailscale / Pomerium / oauth2-proxy**

---

## Method 1: OpenID Connect (OIDC / OAuth 2.0)

Nebulae implements the standard OpenID Connect Authorization Code flow with discovery (`.well-known/openid-configuration`).

### Nebulae Configuration

Add the following environment variables to `docker-compose.yml`:

```yaml
environment:
  - USE_PROXY_FIX=True
  - OIDC_ENABLED=True
  - OIDC_CLIENT_ID=nebulae
  - OIDC_CLIENT_SECRET=YOUR_CLIENT_SECRET
  - OIDC_DISCOVERY_URL=https://auth.example.com/.well-known/openid-configuration
  - OIDC_PROVIDER_NAME=SSO       # Or "Authelia", "Authentik", "Keycloak"
  - OIDC_ADMIN_GROUP=admins       # Grants Nebulae admin rights to members
  - OIDC_LOGOUT_URL=https://auth.example.com/logout
```

| Variable | Description | Default |
| :--- | :--- | :--- |
| `OIDC_ENABLED` | Enables or disables OIDC SSO | Auto-detected if client ID and discovery URL are present |
| `OIDC_CLIENT_ID` | Client ID registered in your IdP | `None` |
| `OIDC_CLIENT_SECRET` | Client secret from your IdP | `None` |
| `OIDC_DISCOVERY_URL` | OIDC discovery endpoint or issuer URL | `None` |
| `OIDC_PROVIDER_NAME` | Text displayed on the login button (`Sign in with <NAME>`) | `SSO` |
| `OIDC_SCOPES` | Scopes requested | `openid profile email groups` |
| `OIDC_ADMIN_GROUP` | IdP group name mapped to Nebulae `admin` role | `admins` |
| `OIDC_LOGOUT_URL` | Redirect target on logout for single sign-out | `None` |
| `OIDC_REDIRECT_URI` | Explicit callback URI (optional) | `https://<NODE_HOSTNAME>/auth/oidc/callback` |

!!! warning "Important: Ensure `profile` and `email` Scopes Are Allowed"
    Identity Providers (like Authelia, Authentik, and Keycloak) only include basic token claims (`sub`, `iss`, `aud`) in the ID token. The actual user attributes (`preferred_username`, `email`, `name`, `groups`) are served from the OIDC `/userinfo` endpoint and **require** the `profile` and `email` scopes.

    Ensure that your IdP client definition includes `profile` and `email` in its allowed scopes. If `profile` is omitted, the IdP will withhold the username, causing Nebulae to fall back to a generated subject identifier (e.g. `user_31384f72`).

---

### Identity Provider Examples

=== "Authelia"
    In Authelia's `configuration.yml`:
    ```yaml
    identity_providers:
      oidc:
        clients:
          - client_id: nebulae
            client_name: Nebulae
            client_secret: '$pbkdf2-sha512$...'
            public: false
            authorization_policy: two_factor # or one_factor
            redirect_uris:
              - https://nebulae.example.com/auth/oidc/callback
            scopes:
              - openid
              - profile
              - email
              - groups
            userinfo_signed_response_alg: none
    ```

=== "Authentik"
    1. In Authentik, go to **Applications** &rarr; **Providers** &rarr; **Create Provider**.
    2. Choose **OAuth2/OpenID Provider**.
    3. Set **Client Type** to *Confidential*.
    4. Set **Redirect URIs** to `https://nebulae.example.com/auth/oidc/callback`.
    5. Set **Signing Key** and ensure `openid`, `email`, `profile` scopes are enabled.
    6. Create an Application in Authentik linked to this provider.
    7. In Nebulae, set `OIDC_DISCOVERY_URL=https://authentik.example.com/application/o/nebulae/.well-known/openid-configuration`.

=== "Keycloak"
    1. Create a client with **Client ID** `nebulae` and **Client Authentication** turned *On*.
    2. Add **Valid Redirect URIs**: `https://nebulae.example.com/auth/oidc/callback`.
    3. Copy the Client Secret from the **Credentials** tab.
    4. In Nebulae, set `OIDC_DISCOVERY_URL=https://keycloak.example.com/realms/<REALM_NAME>/.well-known/openid-configuration`.

---

## Method 2: Reverse Proxy ForwardAuth (Headers)

If running behind a reverse proxy that performs authentication (e.g., Traefik ForwardAuth, NGINX `auth_request`, Caddy, Cloudflare Access, Pomerium, Tailscale), Nebulae can authenticate users directly from trusted HTTP headers.

### Nebulae Configuration

```yaml
environment:
  - USE_PROXY_FIX=True
  - PROXY_AUTH_ENABLED=True
  - PROXY_AUTH_USER_HEADER=Remote-User       # or X-Forwarded-User, Cf-Access-Authenticated-User-Email
  - PROXY_AUTH_EMAIL_HEADER=Remote-Email
  - PROXY_AUTH_NAME_HEADER=Remote-Name
  - PROXY_AUTH_GROUPS_HEADER=Remote-Groups
  - PROXY_AUTH_ADMIN_GROUP=admins
  - PROXY_AUTH_TRUSTED_PROXIES=127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
  - PROXY_AUTH_LOGOUT_URL=https://auth.example.com/logout
```

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PROXY_AUTH_ENABLED` | Enables reverse proxy header authentication | `False` |
| `PROXY_AUTH_USER_HEADER` | Header containing the username/identity | `Remote-User` |
| `PROXY_AUTH_EMAIL_HEADER` | Header containing the user's email | `Remote-Email` |
| `PROXY_AUTH_NAME_HEADER` | Header containing the display name | `Remote-Name` |
| `PROXY_AUTH_GROUPS_HEADER` | Header containing comma-separated groups | `Remote-Groups` |
| `PROXY_AUTH_ADMIN_GROUP` | Group mapped to admin privileges | `admins` |
| `PROXY_AUTH_TRUSTED_PROXIES` | CIDRs or IPs allowed to supply headers (or `*`) | Private subnet ranges |
| `PROXY_AUTH_SECRET_HEADER` | Optional custom header for defense-in-depth | `None` |
| `PROXY_AUTH_SECRET_VALUE` | Expected value of `PROXY_AUTH_SECRET_HEADER` | `None` |

---

## Account Provisioning & Synchronization

* **Just-In-Time Provisioning**: New SSO users are automatically created on their first login, with profile defaults and media folders initialized. If an IdP username collides with an existing account, a unique numerical suffix is appended to preserve account isolation.
* **Account Isolation**: SSO accounts are bound to the IdP subject identifier (`sub`). Local password accounts cannot be silently hijacked by external SSO identities.
* **Role Synchronization**: If the user belongs to the configured admin group in the identity provider, Nebulae automatically synchronizes `admin` permissions on each login and request.
* **Username Resolution**: Nebulae checks claims in order of priority: `preferred_username` &rarr; `username` &rarr; `nickname` &rarr; `upn` &rarr; `name` &rarr; `email` prefix &rarr; `user_<sub[:8]>` (fallback).
* **Automatic Fallback Recovery**: If an account was previously created with a temporary fallback name (`user_xxxxxx`) due to missing scopes, Nebulae will automatically rename it to the resolved IdP username on the next login once claims are available, provided the name is not taken.
