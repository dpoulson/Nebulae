# utils/sso.py
"""
Single Sign-On (SSO) integration utilities supporting:
1. OpenID Connect (OIDC / OAuth 2.0) via Authlib (for Authelia, Keycloak, etc.)
2. Reverse Proxy ForwardAuth headers (Traefik, NGINX, Caddy with Authelia)
"""

import os
import re
import uuid
import ipaddress
import logging
from flask import current_app, session, request
from db_queries.users import (
    get_user_by_username, get_user_by_email, get_user_by_auth_sub,
    add_sso_user, link_user_to_sso, update_user_role, update_user_sso_info,
    create_user_session
)

logger = logging.getLogger(__name__)

oauth = None
_oauth_client = None

def init_sso(app):
    """
    Initializes OIDC and Reverse Proxy (ForwardAuth) configuration.
    """
    global oauth, _oauth_client

    # 1. Reverse Proxy / Forward Auth Configuration
    app.config.setdefault(
        'PROXY_AUTH_ENABLED',
        os.environ.get('PROXY_AUTH_ENABLED', 'False').lower() in ('true', '1', 't')
    )
    app.config.setdefault(
        'PROXY_AUTH_USER_HEADER',
        os.environ.get('PROXY_AUTH_USER_HEADER', 'Remote-User')
    )
    app.config.setdefault(
        'PROXY_AUTH_EMAIL_HEADER',
        os.environ.get('PROXY_AUTH_EMAIL_HEADER', 'Remote-Email')
    )
    app.config.setdefault(
        'PROXY_AUTH_NAME_HEADER',
        os.environ.get('PROXY_AUTH_NAME_HEADER', 'Remote-Name')
    )
    app.config.setdefault(
        'PROXY_AUTH_GROUPS_HEADER',
        os.environ.get('PROXY_AUTH_GROUPS_HEADER', 'Remote-Groups')
    )
    app.config.setdefault(
        'PROXY_AUTH_ADMIN_GROUP',
        os.environ.get('PROXY_AUTH_ADMIN_GROUP', 'admins')
    )
    app.config.setdefault(
        'PROXY_AUTH_LOGOUT_URL',
        os.environ.get('PROXY_AUTH_LOGOUT_URL', None)
    )
    app.config.setdefault(
        'PROXY_AUTH_TRUSTED_PROXIES',
        os.environ.get('PROXY_AUTH_TRUSTED_PROXIES', '127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16')
    )
    app.config.setdefault(
        'PROXY_AUTH_SECRET_HEADER',
        os.environ.get('PROXY_AUTH_SECRET_HEADER', None)
    )
    app.config.setdefault(
        'PROXY_AUTH_SECRET_VALUE',
        os.environ.get('PROXY_AUTH_SECRET_VALUE', None)
    )

    # 2. OIDC Configuration
    oidc_client_id = os.environ.get('OIDC_CLIENT_ID') or app.config.get('OIDC_CLIENT_ID')
    oidc_client_secret = os.environ.get('OIDC_CLIENT_SECRET') or app.config.get('OIDC_CLIENT_SECRET')
    oidc_discovery_url = (
        os.environ.get('OIDC_DISCOVERY_URL') or os.environ.get('OIDC_ISSUER_URL') or
        app.config.get('OIDC_DISCOVERY_URL') or app.config.get('OIDC_ISSUER_URL')
    )

    app.config['OIDC_CLIENT_ID'] = oidc_client_id
    app.config['OIDC_CLIENT_SECRET'] = oidc_client_secret
    app.config['OIDC_DISCOVERY_URL'] = oidc_discovery_url

    # Auto-enable OIDC if client ID and discovery URL are present unless explicitly set to False
    oidc_enabled_env = os.environ.get('OIDC_ENABLED')
    if oidc_enabled_env is not None:
        oidc_enabled = oidc_enabled_env.lower() in ('true', '1', 't')
    else:
        oidc_enabled = bool(oidc_client_id and oidc_discovery_url)
    app.config['OIDC_ENABLED'] = oidc_enabled

    app.config.setdefault(
        'OIDC_PROVIDER_NAME',
        os.environ.get('OIDC_PROVIDER_NAME', 'SSO')
    )
    app.config.setdefault(
        'OIDC_SCOPES',
        os.environ.get('OIDC_SCOPES', 'openid profile email groups')
    )
    app.config.setdefault(
        'OIDC_ADMIN_GROUP',
        os.environ.get('OIDC_ADMIN_GROUP', 'admins')
    )
    app.config.setdefault(
        'OIDC_LOGOUT_URL',
        os.environ.get('OIDC_LOGOUT_URL', None)
    )
    app.config.setdefault(
        'OIDC_REDIRECT_URI',
        os.environ.get('OIDC_REDIRECT_URI', None)
    )

    # ProxyFix integration for correct scheme and remote IP behind reverse proxies
    use_proxy_fix = os.environ.get('USE_PROXY_FIX', 'False').lower() in ('true', '1', 't')
    if use_proxy_fix or app.config.get('PROXY_AUTH_ENABLED'):
        try:
            from werkzeug.middleware.proxy_fix import ProxyFix

            class RawPeerProxyFix(ProxyFix):
                def __call__(self, environ, start_response):
                    # Capture physical socket peer IP before ProxyFix rewrites REMOTE_ADDR
                    environ['RAW_REMOTE_ADDR'] = environ.get('REMOTE_ADDR')
                    return super().__call__(environ, start_response)

            app.wsgi_app = RawPeerProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
            logger.info("ProxyFix middleware enabled for reverse proxy support.")
        except Exception as e:
            logger.warning(f"Could not enable ProxyFix: {e}")

    # Register OIDC client with Authlib
    if app.config.get('OIDC_ENABLED'):
        try:
            from authlib.integrations.flask_client import OAuth

            formatted_discovery_url = oidc_discovery_url
            if formatted_discovery_url and not formatted_discovery_url.endswith('.well-known/openid-configuration'):
                formatted_discovery_url = formatted_discovery_url.rstrip('/') + '/.well-known/openid-configuration'
            app.config['OIDC_DISCOVERY_URL'] = formatted_discovery_url

            oauth = OAuth(app)
            _oauth_client = oauth.register(
                name='oidc',
                client_id=oidc_client_id,
                client_secret=oidc_client_secret,
                server_metadata_url=formatted_discovery_url,
                client_kwargs={
                    'scope': app.config.get('OIDC_SCOPES', 'openid profile email groups')
                }
            )
            logger.info(f"OIDC registered successfully for provider: {app.config['OIDC_PROVIDER_NAME']}")
        except Exception as e:
            logger.error(f"Failed to initialize OIDC client with Authlib: {e}")


def get_oauth_client():
    """Returns the registered Authlib OAuth client for OIDC."""
    global _oauth_client
    return _oauth_client


def is_trusted_proxy(client_ip, trusted_proxies_str):
    """
    Checks if client_ip belongs to trusted IP / CIDR list or '*'.
    """
    if not trusted_proxies_str:
        return False
    if trusted_proxies_str.strip() == '*':
        return True

    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for item in trusted_proxies_str.split(','):
        item = item.strip()
        if not item:
            continue
        try:
            if '/' in item:
                if ip in ipaddress.ip_network(item, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(item):
                    return True
        except ValueError:
            continue
    return False


def normalize_sso_username(raw_username):
    """
    Sanitizes raw username into safe alphanumeric string.
    """
    if not raw_username:
        return f"user_{uuid.uuid4().hex[:8]}"
    username = str(raw_username).strip()
    if '@' in username:
        username = username.split('@')[0]
    username = re.sub(r'[^\w\.-]', '_', username)
    return username[:40] or f"user_{uuid.uuid4().hex[:8]}"


def parse_groups(groups):
    """
    Normalizes groups claim or header into a list of lowercase group names.
    """
    if not groups:
        return []
    if isinstance(groups, list):
        return [str(g).strip().lower() for g in groups if g]
    if isinstance(groups, str):
        return [g.strip().lower() for g in groups.split(',') if g.strip()]
    return []


def login_or_provision_sso_user(username, email=None, display_name=None, groups=None, auth_provider='oidc', auth_sub=None, admin_group=None):
    """
    Finds or provisions an SSO user, synchronizes role, creates DB session,
    and sets Flask session keys.
    """
    target_admin_group = (admin_group or current_app.config.get('OIDC_ADMIN_GROUP', 'admins')).lower()
    user_groups = parse_groups(groups)
    is_admin = target_admin_group in user_groups

    user = None

    # 1. Lookup solely by explicit auth_sub to prevent hijacking existing local accounts
    if auth_sub:
        user = get_user_by_auth_sub(auth_sub)

    if user:
        # Check if this user record has a fallback 'user_<sub[:8]>' username from an earlier login,
        # and we now have the actual username from the IdP. Only rename if not colliding with another user.
        clean_user = normalize_sso_username(username) if username else None
        if user['username'].startswith('user_') and clean_user and not clean_user.startswith('user_'):
            if get_user_by_username(clean_user) is None:
                from db_queries.users import update_username
                update_username(user['id'], clean_user)
                user['username'] = clean_user

        # Synchronize admin status for SSO accounts
        if user.get('auth_provider') != 'local':
            if is_admin and user['user_type'] != 'admin':
                update_user_role(user['id'], 'admin')
                user['user_type'] = 'admin'
            elif not is_admin and user['user_type'] == 'admin':
                update_user_role(user['id'], 'user')
                user['user_type'] = 'user'

        # Update display name / email if not already present
        updates = {}
        if display_name and not user.get('display_name'):
            updates['display_name'] = display_name
        if email and not user.get('email'):
            updates['email'] = email
        if updates:
            update_user_sso_info(user['id'], **updates)
            user.update(updates)
    else:
        # 2. Auto-provision new user
        clean_username = normalize_sso_username(username)
        candidate = clean_username
        counter = 1
        while get_user_by_username(candidate) is not None:
            candidate = f"{clean_username}_{counter}"
            counter += 1

        final_display_name = display_name or candidate
        final_email = email or candidate
        role = 'admin' if is_admin else 'user'

        add_sso_user(
            username=candidate,
            email=final_email,
            display_name=final_display_name,
            user_type=role,
            auth_provider=auth_provider,
            auth_sub=auth_sub
        )
        user = get_user_by_username(candidate)

    if not user:
        raise RuntimeError(f"Failed to retrieve or provision user record for SSO user: {username}")

    # 3. Create persistent DB session and populate Flask session
    session.clear()
    session['username'] = user['username']
    session['is_admin'] = (user['user_type'] == 'admin')
    session['auth_provider'] = auth_provider
    session_id = str(uuid.uuid4())
    session['session_id'] = session_id
    session.permanent = True

    create_user_session(
        user['id'],
        session_id,
        request.user_agent.string if request.user_agent else 'SSO Client',
        request.remote_addr or '127.0.0.1'
    )
    return user
