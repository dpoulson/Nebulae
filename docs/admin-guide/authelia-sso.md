# Authelia Single Sign-On (SSO) Integration

Nebulae supports single sign-on (SSO) integration with [Authelia](https://www.authelia.com/) through two methods:

1. **OpenID Connect (OIDC)**: Standard OAuth 2.0 / OIDC redirect flow with a "Sign in with Authelia" button.
2. **Reverse Proxy ForwardAuth**: Seamless header-based single sign-on passed through Traefik, NGINX, or Caddy.

Both approaches leverage Authelia to handle authentication, multi-factor authentication (MFA/2FA via TOTP, WebAuthn, or Duo), and backend user directories like **LDAP, Active Directory, or LLDAP**.

---

## Method 1: OpenID Connect (OIDC) Setup (Recommended)

In this setup, Authelia functions as an OpenID Connect Identity Provider (IdP) and Nebulae acts as an OIDC client (Relying Party).

### 1. Configure Authelia

In your Authelia `configuration.yml`, register Nebulae under the `identity_providers.oidc.clients` section:

```yaml
identity_providers:
  oidc:
    cors:
      endpoints:
        - authorization
        - token
        - revocation
        - introspection
        - userinfo
      allowed_origins_from_client_redirect_uris: true
    clients:
      - client_id: nebulae
        client_name: Nebulae Social Platform
        client_secret: '$pbkdf2-sha512$...' # Generate with: docker run authelia/authelia:latest authelia crypto hash generate pbkdf2 --variant sha512 -p <YOUR_PLAINTEXT_SECRET>
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

### 2. Configure Nebulae

Add the following environment variables to your Nebulae service in `docker-compose.yml`:

```yaml
environment:
  - USE_PROXY_FIX=True
  - OIDC_ENABLED=True
  - OIDC_CLIENT_ID=nebulae
  - OIDC_CLIENT_SECRET=YOUR_PLAINTEXT_SECRET
  - OIDC_DISCOVERY_URL=https://auth.example.com/.well-known/openid-configuration
  - OIDC_PROVIDER_NAME=Authelia
  - OIDC_ADMIN_GROUP=admins
  - OIDC_LOGOUT_URL=https://auth.example.com/logout
```

| Variable | Description | Default |
| :--- | :--- | :--- |
| `OIDC_ENABLED` | Enables or disables OIDC SSO | Auto-detected from `OIDC_CLIENT_ID` |
| `OIDC_CLIENT_ID` | Client ID registered in Authelia | `None` |
| `OIDC_CLIENT_SECRET` | Client secret matching Authelia | `None` |
| `OIDC_DISCOVERY_URL` | OpenID configuration endpoint | `None` |
| `OIDC_PROVIDER_NAME` | Name shown on the login button | `Authelia` |
| `OIDC_ADMIN_GROUP` | Authelia group name mapped to admin role | `admins` |
| `OIDC_LOGOUT_URL` | Redirect target when user logs out | `None` |
| `OIDC_REDIRECT_URI` | Optional explicit callback URL | Auto-generated from host |

---

## Method 2: Reverse Proxy ForwardAuth (Headers)

In this setup, Authelia intercepts all requests at your reverse proxy and injects headers after authenticating the user.

### 1. Reverse Proxy Configuration Examples

#### Traefik ForwardAuth Middleware
```yaml
http:
  middlewares:
    authelia:
      forwardAuth:
        address: http://authelia:9091/api/authz/forward-auth
        trustForwardHeader: true
        authResponseHeaders:
          - Remote-User
          - Remote-Email
          - Remote-Name
          - Remote-Groups
```

#### NGINX `auth_request` Configuration
```nginx
location / {
    auth_request /authelia;
    auth_request_set $user $upstream_http_remote_user;
    auth_request_set $email $upstream_http_remote_email;
    auth_request_set $name $upstream_http_remote_name;
    auth_request_set $groups $upstream_http_remote_groups;

    proxy_set_header Remote-User $user;
    proxy_set_header Remote-Email $email;
    proxy_set_header Remote-Name $name;
    proxy_set_header Remote-Groups $groups;

    proxy_pass http://nebulae:5000;
}
```

### 2. Configure Nebulae

Add the following environment variables to your Nebulae service in `docker-compose.yml`:

```yaml
environment:
  - USE_PROXY_FIX=True
  - PROXY_AUTH_ENABLED=True
  - PROXY_AUTH_USER_HEADER=Remote-User
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
| `PROXY_AUTH_USER_HEADER` | Header containing the username | `Remote-User` |
| `PROXY_AUTH_EMAIL_HEADER` | Header containing the user's email | `Remote-Email` |
| `PROXY_AUTH_NAME_HEADER` | Header containing the display name | `Remote-Name` |
| `PROXY_AUTH_GROUPS_HEADER` | Header containing comma-separated groups | `Remote-Groups` |
| `PROXY_AUTH_ADMIN_GROUP` | Group granting admin privileges | `admins` |
| `PROXY_AUTH_TRUSTED_PROXIES` | CIDRs or IPs allowed to pass headers | Private subnet ranges |
| `PROXY_AUTH_LOGOUT_URL` | Redirect target on logout | `None` |

---

## User Provisioning & Account Linking

* **Just-In-Time Provisioning**: When a user logs in via Authelia for the first time, Nebulae automatically creates their local account profile and uploads directory.
* **Automatic Account Linking**: If a local account with the matching email or username already exists, Nebulae links the account to Authelia on first SSO sign-in.
* **Role Synchronization**: If a user is a member of the configured `admins` group in Authelia/LDAP, Nebulae automatically grants admin rights.
