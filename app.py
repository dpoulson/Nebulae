# app.py
import logging

logger = logging.getLogger(__name__)

from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_from_directory, jsonify, make_response, current_app
import os
import hashlib
import glob
from urllib.parse import quote, unquote
import json
from werkzeug.utils import secure_filename
import base64
import shutil
import datetime
import re
import traceback
import sys
import hmac
from itsdangerous import URLSafeTimedSerializer
from markupsafe import Markup, escape
from flask_compress import Compress
from routes.conversations import conversations_bp



# Import database functions and utilities
from db import get_db, close_db, init_db
# MODIFICATION: Import session management functions
from db_queries.users import get_user_id_by_username, get_user_by_id, get_user_by_username, get_session_by_id, update_session_last_seen, update_user_role
from db_queries.notifications import get_unread_notification_count, check_and_create_birthday_notifications
from db_queries.federation import get_node_by_hostname, get_node_nu_id
# NEW: Import settings queries
from db_queries.settings import get_user_settings

from utils.auth import hash_password, check_password
from utils.media import list_media_content, allowed_file, get_media_by_id, update_media_alt_text
from utils.text_processing import linkify_mentions # NEW: Import the mention linkify function
from utils.text_processing import linkify_urls # NEW: Import the url linkify function
from utils.text_processing import linkify_everyone_mention # XSS FIX: replaces the old `| replace()` chain in templates
from routes.push_notifications import push_notifications_bp
from routes.parental import parental_bp
from routes.shortcuts import shortcuts_bp
from utils.sso import init_sso, is_trusted_proxy, login_or_provision_sso_user, parse_groups

# Application version
__version__ = "0.9.6.6-beta"

# Configure logging before anything else emits a line, so that LOG_LEVEL
# actually governs the whole startup sequence.
from utils.logging_setup import configure_logging
configure_logging()

app = Flask(__name__)
Compress(app)
# Load secret key from environment variable.
# IMPORTANT: In a production environment, this should be a long, random, and securely stored string.
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    logger.warning("SECRET_KEY environment variable not set. Using a temporary, insecure key. User sessions will not persist across restarts.")
    SECRET_KEY = os.urandom(24)
app.secret_key = SECRET_KEY
configure_logging(app)


# Define the path for the SQLite database file
DATABASE = os.path.join(app.instance_path, 'social_node.db')

# Define the base directory inside the container where user media volumes are mounted (READ-ONLY)
#USER_MEDIA_BASE_DIR = '/app/user_media'
USER_MEDIA_BASE_DIR = os.environ.get('USER_MEDIA_BASE_DIR', '/app/user_media')

# Define the base directory for user uploads (WRITABLE)
#USER_UPLOADS_BASE_DIR = '/app/user_uploads'
USER_UPLOADS_BASE_DIR = os.environ.get('USER_UPLOADS_BASE_DIR', '/app/user_uploads')

# Define the base directory for profile pictures (WRITABLE)
#PROFILE_PICTURE_STORAGE_DIR = '/app/profile_pictures_storage'
PROFILE_PICTURE_STORAGE_DIR = os.environ.get('PROFILE_PICTURE_STORAGE_DIR', '/app/profile_pictures_storage')

# Define the base directory for thumbnails (WRITABLE)
#THUMBNAIL_CACHE_DIR = '/app/thumbnails'
THUMBNAIL_CACHE_DIR = os.environ.get('THUMBNAIL_CACHE_DIR', '/app/thumbnails')

# Allowed extensions for profile pictures
ALLOWED_PROFILE_PICTURE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# NEW: Define allowed extensions for general media (posts, comments)
ALLOWED_MEDIA_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'mp4', 'mov', 'webm', 'avi', 'mkv'}


# Ensure the instance folder and profile picture storage folder exist
os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(PROFILE_PICTURE_STORAGE_DIR, exist_ok=True)
os.makedirs(THUMBNAIL_CACHE_DIR, exist_ok=True)  # Create thumbnails directory

# Pass constants to the app config for access in other modules if needed
app.config['DATABASE'] = DATABASE
app.config['USER_MEDIA_BASE_DIR'] = USER_MEDIA_BASE_DIR
app.config['USER_UPLOADS_BASE_DIR'] = USER_UPLOADS_BASE_DIR
app.config['PROFILE_PICTURE_STORAGE_DIR'] = PROFILE_PICTURE_STORAGE_DIR
app.config['THUMBNAIL_CACHE_DIR'] = THUMBNAIL_CACHE_DIR
app.config['ALLOWED_PROFILE_PICTURE_EXTENSIONS'] = ALLOWED_PROFILE_PICTURE_EXTENSIONS
# NEW: Add the new media extensions to the app config
app.config['ALLOWED_MEDIA_EXTENSIONS'] = ALLOWED_MEDIA_EXTENSIONS


app.config['NODE_HOSTNAME'] = os.environ.get('NODE_HOSTNAME')
app.config['FEDERATION_INSECURE_MODE'] = os.environ.get('FEDERATION_INSECURE_MODE', 'False').lower() in ('true', '1', 't')

# Add compression config
app.config['COMPRESS_MIMETYPES'] = [
       'text/html',
       'text/css',
       'text/xml',
       'application/json',
       'application/javascript',
       'text/javascript',
       'image/svg+xml'
   ]
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 500
# Persistent session lifetime - keeps PWA/browser sessions alive for 30 days
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# ---------------------------------------------------------------------------
# Session cookie hardening
#
# SameSite=Lax is the important one: it stops other sites making authenticated
# cross-site POSTs to this node (CSRF), while still allowing top-level GET
# navigations - which is exactly what the federated ?viewer_token= links use.
#
# SESSION_COOKIE_SECURE tells the browser to only send the cookie over HTTPS.
# It defaults to on, but switches off automatically when the node is running in
# FEDERATION_INSECURE_MODE (an HTTP test setup). It can also be forced either
# way with the SESSION_COOKIE_SECURE env var, for LAN-only installs served
# over plain HTTP.
# ---------------------------------------------------------------------------
_secure_cookie_env = os.environ.get('SESSION_COOKIE_SECURE')
if _secure_cookie_env is not None:
    _secure_cookies = _secure_cookie_env.lower() in ('true', '1', 't', 'yes')
else:
    _secure_cookies = not app.config['FEDERATION_INSECURE_MODE']

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = _secure_cookies

logger.info(f"Session cookies: SameSite=Lax, HttpOnly=True, Secure={_secure_cookies}")
if not _secure_cookies:
    print("WARNING: Session cookies are not marked Secure. This is expected on an "
          "HTTP-only test or LAN install, but should NEVER be used on a public "
          "node. Set SESSION_COOKIE_SECURE=True once HTTPS is in place.")

# Application version
app.config['APP_VERSION'] = __version__

# Register database connection/teardown functions
app.teardown_appcontext(close_db)

# Call init_db() when the application starts
with app.app_context():
    init_db(app) # Pass app to init_db for app.open_resource
    init_sso(app) # Initialize Single Sign-On (OIDC & Proxy Auth)

# Start the background scheduler for periodic tasks
from utils.scheduler import scheduler
scheduler.init_app(app)
scheduler.start()

# Federation Recovery: On startup, request any missed payloads from connected nodes
def _federation_recovery():
    """
    On startup, requests any federated payloads missed while this node was offline
    and replays them through local endpoints. Runs once per process in background.
    """
    import time
    import requests as _req
    import json as _json
    import hmac as _hmac
    import hashlib as _hash
    from utils.federation_utils import get_remote_node_api_url

    time.sleep(8)  # Wait for gunicorn workers to fully bind

    with app.app_context():
        try:
            from db_queries.federation import (
                get_all_connected_nodes, update_node_last_sync
            )
            from datetime import datetime, timedelta

            nodes = [n for n in get_all_connected_nodes()
                     if n['status'] == 'connected'
                     and n.get('shared_secret')
                     and n.get('connection_type') == 'full']

            if not nodes:
                logger.warning("federation_recovery: No connected full nodes, skipping.")
                return

            local_hostname = app.config.get('NODE_HOSTNAME')
            insecure_mode = app.config.get('FEDERATION_INSECURE_MODE', False)
            # Always use internal container port - external port mapping is irrelevant here
            local_base = "http://127.0.0.1:5000"

            for node in nodes:
                hostname = node['hostname']
                shared_secret = node['shared_secret']

                # Use last_sync_at if we have it, otherwise fall back to 24 hours ago
                since = node.get('last_sync_at')
                if not since:
                    since = (datetime.utcnow() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')

                try:
                    # Step 1: Ask remote node for everything it tried to send us since `since`
                    req_payload = _json.dumps({'since': since}, sort_keys=True).encode('utf-8')
                    sig = _hmac.new(
                        shared_secret.encode('utf-8'),
                        msg=req_payload,
                        digestmod=_hash.sha256
                    ).hexdigest()
                    catchup_headers = {
                        'Content-Type': 'application/json',
                        'X-Node-Hostname': local_hostname,
                        'X-Node-Signature': sig
                    }
                    catchup_url = get_remote_node_api_url(
                        hostname, '/federation/api/v1/catchup', insecure_mode
                    )
                    response = _req.post(
                        catchup_url, data=req_payload, headers=catchup_headers,
                        timeout=30, verify=not insecure_mode
                    )
                    response.raise_for_status()

                    items = response.json().get('items', [])
                    if not items:
                        logger.info(f"federation_recovery: No missed items from {hostname}.")
                        update_node_last_sync(hostname)
                        continue

                    logger.info(f"federation_recovery: Replaying {len(items)} missed items from {hostname}.")

                    # Step 2: Replay each item against our own local endpoints.
                    # We sign as the remote node so @signature_required accepts them normally.
                    # All existing handlers are already idempotent (CUIDs, msg_uids, etc.)
                    processed = 0
                    for item in items:
                        endpoint = item.get('endpoint')
                        method = item.get('method', 'POST')
                        payload_dict = item.get('payload', {})

                        if not endpoint or not payload_dict:
                            continue

                        try:
                            replay_body = _json.dumps(payload_dict, sort_keys=True).encode('utf-8')
                            replay_sig = _hmac.new(
                                shared_secret.encode('utf-8'),
                                msg=replay_body,
                                digestmod=_hash.sha256
                            ).hexdigest()
                            replay_headers = {
                                'Content-Type': 'application/json',
                                'X-Node-Hostname': hostname,
                                'X-Node-Signature': replay_sig
                            }
                            local_url = f"{local_base}{endpoint}"
                            # Fire and don't stress about the response status —
                            # 404s for already-deleted content are expected and harmless
                            _req.request(
                                method, local_url, data=replay_body,
                                headers=replay_headers, timeout=10
                            )
                            processed += 1
                        except Exception as item_err:
                            logger.error(f"federation_recovery: Failed to replay {endpoint}: {item_err}")

                    logger.info(f"federation_recovery: Replayed {processed}/{len(items)} items from {hostname}.")
                    update_node_last_sync(hostname)

                except _req.RequestException as e:
                    logger.error(f"federation_recovery: Could not reach {hostname} (still offline?): {e}")
                except Exception as e:
                    logger.error(f"federation_recovery: Unexpected error for {hostname}: {e}")
                    logger.exception("Unhandled exception")

        except Exception as e:
            logger.error(f"federation_recovery: Fatal startup error: {e}")
            logger.exception("Unhandled exception")

import threading
_recovery_thread = threading.Thread(target=_federation_recovery, daemon=True)
_recovery_thread.start()

@app.before_request
def before_request_tasks():
    """
    This function runs before each request.
    It's used here to trigger daily tasks, validate sessions,
    and load request-scoped context.
    """
    # 0. Proxy Authentication (ForwardAuth) if enabled
    if current_app.config.get('PROXY_AUTH_ENABLED'):
        user_header = current_app.config.get('PROXY_AUTH_USER_HEADER', 'Remote-User')
        remote_user = request.headers.get(user_header)
        if remote_user:
            peer_ip = request.environ.get('RAW_REMOTE_ADDR', request.remote_addr)
            trusted_proxies = current_app.config.get('PROXY_AUTH_TRUSTED_PROXIES')
            if is_trusted_proxy(peer_ip, trusted_proxies):
                secret_hdr = current_app.config.get('PROXY_AUTH_SECRET_HEADER')
                secret_val = current_app.config.get('PROXY_AUTH_SECRET_VALUE')
                secret_ok = True
                if secret_hdr:
                    sent_val = request.headers.get(secret_hdr, '')
                    secret_ok = bool(secret_val and hmac.compare_digest(sent_val, secret_val))
                if secret_ok:
                    curr_user = session.get('username')
                    groups_hdr = current_app.config.get('PROXY_AUTH_GROUPS_HEADER', 'Remote-Groups')
                    admin_grp = current_app.config.get('PROXY_AUTH_ADMIN_GROUP', 'admins')
                    if curr_user != remote_user or 'session_id' not in session:
                        email_hdr = current_app.config.get('PROXY_AUTH_EMAIL_HEADER', 'Remote-Email')
                        name_hdr = current_app.config.get('PROXY_AUTH_NAME_HEADER', 'Remote-Name')
                        try:
                            login_or_provision_sso_user(
                                username=remote_user,
                                email=request.headers.get(email_hdr),
                                display_name=request.headers.get(name_hdr),
                                groups=request.headers.get(groups_hdr),
                                auth_provider='proxy',
                                auth_sub=f"proxy:{remote_user}",
                                admin_group=admin_grp
                            )
                        except Exception as e:
                            logger.error(f"Proxy authentication failed for {remote_user}: {e}")
                    else:
                        # Keep admin status synchronized with proxy groups on subsequent requests
                        user_groups = parse_groups(request.headers.get(groups_hdr))
                        is_admin = admin_grp.lower() in user_groups
                        if session.get('is_admin') != is_admin:
                            user = get_user_by_username(curr_user)
                            if user and user.get('auth_provider') == 'proxy':
                                update_user_role(user['id'], 'admin' if is_admin else 'user')
                                session['is_admin'] = is_admin

    # 1. Validate the current user's session
    if 'session_id' in session:
        session_valid = get_session_by_id(session['session_id'])
        if not session_valid:
            session.clear()
            flash('Your session was logged out from another device.', 'info')
        else:
            # If the session is valid, update its last_seen timestamp
            update_session_last_seen(session['session_id'])

    # 2. Trigger daily tasks
    check_and_create_birthday_notifications()
    
    # 3. Load request-scoped context
    g.nu_id = get_node_nu_id()


# --- NEW: Jinja2 Filter for JSON parsing ---
@app.template_filter('from_json')
def from_json_filter(s):
    """
    Converts a JSON string to a Python object.
    Used to parse tagged_user_puids from posts.
    Returns empty list if parsing fails or input is None.
    """
    if not s:
        return []
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return []


# --- Context Processor to make functions available in Jinja2 templates ---
@app.context_processor
def inject_user_data_functions():
    """
    Makes functions and data available globally in Jinja2 templates.
    """
    from db_queries.users import get_user_by_username, get_username_by_id, get_user_by_id, get_user_by_puid
    
    unread_notifications = 0
    # DARK MODE FIX: Get default settings first. These will be overridden by user-specific
    # or federated settings if they exist.
    user_settings = get_user_settings(None)

    # NEW: Initialize parent status variables
    is_parent = False
    pending_approvals_count = 0
    
    unread_messages_count = 0  # ← add this initialisation next to unread_notifications = 0

    current_user = None

    if session.get('is_federated_viewer'):
        federated_settings = session.get('federated_viewer_settings')
        if federated_settings:
            user_settings.update(federated_settings)
    elif 'username' in session:
        current_user = get_user_by_username(session['username'])
        if current_user:
            user_id = current_user['id']
            unread_notifications = get_unread_notification_count(user_id)
            user_settings = get_user_settings(user_id)
            from db_queries.conversations import get_unread_conversation_count_for_user
            unread_messages_count = get_unread_conversation_count_for_user(user_id)

            # NEW: Check if user is a parent
            from db_queries.parental_controls import get_children_for_parent, get_pending_approvals_count_for_parent
            children = get_children_for_parent(user_id)
            is_parent = len(children) > 0
            pending_approvals_count = get_pending_approvals_count_for_parent(user_id) if is_parent else 0

    def federated_user_profile_url(user_object):
        """
        Generates a profile URL for a user object.
        For remote users, it generates a full URL with a short-lived, signed
        viewer token if a local user is logged in.
        """
        if not user_object:
            return "#"
        
        try:
            puid = user_object['puid']
            if not puid:
                return "#"
        except (KeyError, TypeError):
            return "#"

        if 'hostname' in user_object and user_object['hostname']:
            remote_hostname = user_object['hostname']
            
            viewer_puid = None
            local_user = None # Keep a reference to the full user object
            if 'username' in session and not session.get('is_federated_viewer'):
                local_user = get_user_by_username(session['username'])
                if local_user:
                    viewer_puid = local_user['puid']

            insecure_mode = current_app.config.get('FEDERATION_INSECURE_MODE', False)
            protocol = "http" if insecure_mode else "https"
            base_url = f"{protocol}://{remote_hostname}/u/{puid}"

            if viewer_puid and local_user:
                node = get_node_by_hostname(remote_hostname)
                
                if node and node['status'] == 'connected' and node['shared_secret']:
                    serializer = URLSafeTimedSerializer(node['shared_secret'])
                    
                    # DARK MODE FIX: Get the settings for the logged-in local user.
                    local_user_settings = get_user_settings(local_user['id'])
                    
                    payload = {
                        'viewer_puid': viewer_puid,
                        'origin_hostname': current_app.config.get('NODE_HOSTNAME'),
                        # DARK MODE FIX: Add the settings to the token payload.
                        'settings': local_user_settings
                    }
                    
                    token = serializer.dumps(payload, salt='viewer-token-salt')
                    return f"{base_url}?viewer_token={token}"

            # If a token can't be generated, return the base URL without it.
            return base_url
        else:
            # Removed accounts have no profile to visit, so don't offer a link.
            try:
                if user_object['user_type'] == 'deleted':
                    return "#"
            except (KeyError, TypeError):
                pass

            # For local users, just generate a standard local URL.
            return url_for('main.user_profile', puid=puid)

    def federated_group_profile_url(group_object):
        """
        Generates a profile URL for a group object, handling remote groups
        with a viewer token, similar to user profiles.
        """
        if not group_object:
            return "#"
        
        try:
            puid = group_object['puid']
            remote_hostname = group_object.get('hostname') or group_object.get('node_hostname')
            if not puid:
                return "#"
        except (KeyError, TypeError):
            return "#"

        if remote_hostname and remote_hostname != 'Local' and remote_hostname != current_app.config.get('NODE_HOSTNAME'):
            viewer_puid = None
            local_user = None # Keep a reference to the full user object
            if 'username' in session and not session.get('is_federated_viewer'):
                local_user = get_user_by_username(session['username'])
                if local_user:
                    viewer_puid = local_user['puid']

            insecure_mode = current_app.config.get('FEDERATION_INSECURE_MODE', False)
            protocol = "http" if insecure_mode else "https"
            base_url = f"{protocol}://{remote_hostname}/group/{puid}"

            if viewer_puid and local_user:
                node = get_node_by_hostname(remote_hostname)
                if node and node['status'] == 'connected' and node['shared_secret']:
                    serializer = URLSafeTimedSerializer(node['shared_secret'])

                    # DARK MODE FIX: Get the settings for the logged-in local user.
                    local_user_settings = get_user_settings(local_user['id'])

                    payload = {
                        'viewer_puid': viewer_puid,
                        'origin_hostname': current_app.config.get('NODE_HOSTNAME'),
                        # DARK MODE FIX: Add the settings to the token payload.
                        'settings': local_user_settings
                    }
                    token = serializer.dumps(payload, salt='viewer-token-salt')
                    return f"{base_url}?viewer_token={token}"
            
            return base_url
        else:
            # For local groups, generate a standard local URL.
            return url_for('groups.group_profile', puid=puid)
            
    def federated_event_profile_url(event_object):
        """
        Generates a profile URL for an event object, handling remote events
        with a viewer token.
        """
        if not event_object:
            return "#"
        
        try:
            puid = event_object['puid']
            remote_hostname = event_object.get('hostname')
            if not puid:
                return "#"
        except (KeyError, TypeError):
            return "#"

        if remote_hostname and remote_hostname != current_app.config.get('NODE_HOSTNAME'):
            viewer_puid = None
            local_user = None
            if 'username' in session and not session.get('is_federated_viewer'):
                local_user = get_user_by_username(session['username'])
                if local_user:
                    viewer_puid = local_user['puid']

            insecure_mode = current_app.config.get('FEDERATION_INSECURE_MODE', False)
            protocol = "http" if insecure_mode else "https"
            base_url = f"{protocol}://{remote_hostname}/events/{puid}"

            if viewer_puid and local_user:
                node = get_node_by_hostname(remote_hostname)
                if node and node['status'] == 'connected' and node['shared_secret']:
                    serializer = URLSafeTimedSerializer(node['shared_secret'])
                    local_user_settings = get_user_settings(local_user['id'])
                    payload = {
                        'viewer_puid': viewer_puid,
                        'origin_hostname': current_app.config.get('NODE_HOSTNAME'),
                        'settings': local_user_settings
                    }
                    token = serializer.dumps(payload, salt='viewer-token-salt')
                    return f"{base_url}?viewer_token={token}"
            
            return base_url
        else:
            return url_for('events.event_profile', puid=puid)

    def federated_event_picture_url(event_object):
        """
        Generates the correct URL for an event's profile picture,
        handling both local and remote events.
        Follows the same pattern as profile pictures and group pictures.
        """
        if not event_object:
            return url_for('static', filename='images/default_avatar.png')
        
        try:
            profile_picture_path = event_object.get('profile_picture_path')
            if not profile_picture_path:
                return url_for('static', filename='images/default_avatar.png')
            
            origin_hostname = event_object.get('hostname')
            current_node_hostname = current_app.config.get('NODE_HOSTNAME')
            
            # If no hostname or hostname matches current node, it's local content
            if not origin_hostname or origin_hostname == current_node_hostname:
                # Local event - use local URL
                return url_for('main.serve_event_picture', filename=profile_picture_path)
            else:
                # Remote event - use federated URL pointing to origin node
                insecure_mode = current_app.config.get('FEDERATION_INSECURE_MODE', False)
                protocol = "http" if insecure_mode else "https"
                return f"{protocol}://{origin_hostname}/event_pictures/{quote(profile_picture_path)}"
                
        except (AttributeError, TypeError, KeyError):
            logger.exception("Unhandled exception")
            return url_for('static', filename='images/default_avatar.png')

    def federated_media_url(item, author_or_filename=None):
        """
        Generates the correct, full URL for media.
        It can handle three cases:
        1. (media_object, author_object) for post media.
        2. (author_object, filename_string) for profile pictures.
        3. (media_item_dict, None) for gallery media with all metadata in one dict.
        """
        try:
            puid = None
            filename = None
            origin_hostname = None
            
            # Case 3: Gallery media - single dict with all metadata (NEW)
            if isinstance(item, dict) and author_or_filename is None and 'origin_hostname' in item and 'media_file_path' in item:
                origin_hostname = item.get('origin_hostname')
                filename = item.get('media_file_path')
                puid = item.get('puid')
            
            # Case 1: For post media, where 'item' is a media_file object (dict)
            # and 'author_or_filename' is the author object (dict).
            elif isinstance(item, dict) and 'media_file_path' in item and isinstance(author_or_filename, dict):
                media_object = item
                author_object = author_or_filename
                
                origin_hostname = media_object.get('origin_hostname') or author_object.get('hostname')
                filename = media_object.get('media_file_path')
                puid = author_object.get('puid')

            # Case 2: For profile pictures, where 'item' is the user object (dict)
            # and 'author_or_filename' is the filename (string).
            elif isinstance(item, dict) and isinstance(author_or_filename, str):
                author_object = item
                filename = author_or_filename
                
                origin_hostname = author_object.get('hostname')
                puid = author_object.get('puid')
            
            else:
                return "#"

            if not puid or not filename:
                return "#"

            # If the origin_hostname is the same as our own node's hostname
            # (or if it's None, meaning it's local content), generate a local URL.
            # Otherwise, generate a full remote URL.
            current_node_hostname = current_app.config.get('NODE_HOSTNAME')
            if not origin_hostname or origin_hostname == current_node_hostname:
                # EVENT ATTENDEE PIC FIX: Check if the item is an attendee object
                if 'profile_picture_path' in item and 'username' not in item:
                     return url_for('main.serve_profile_picture', filename=filename)
                return url_for('main.serve_user_media', puid=puid, filename=filename)
            else:
                insecure_mode = current_app.config.get('FEDERATION_INSECURE_MODE', False)
                protocol = "http" if insecure_mode else "https"
                # EVENT ATTENDEE PIC FIX: Use correct endpoint for profile pictures
                if 'profile_picture_path' in item and 'username' not in item:
                    return f"{protocol}://{origin_hostname}/profile_pictures/{quote(filename)}"
                return f"{protocol}://{origin_hostname}/media/{puid}/{quote(filename)}"

        except (AttributeError, TypeError, KeyError):
            logger.exception("Unhandled exception")
            return "#"
            
    return dict(
        get_user_by_username=get_user_by_username,
        get_username_by_id=get_username_by_id,
        get_user_by_id=get_user_by_id,
        get_user_by_puid=get_user_by_puid,  # NEW: For tagged users lookup
        unread_notification_count=unread_notifications,
        unread_messages_count=unread_messages_count,
        federated_user_profile_url=federated_user_profile_url,
        federated_media_url=federated_media_url,
        federated_group_profile_url=federated_group_profile_url,
        federated_event_profile_url=federated_event_profile_url,
        federated_event_picture_url=federated_event_picture_url,
        # NEW: Make user settings available in all templates
        user_settings=user_settings,
        current_user=current_user,
        is_parent=is_parent,
        pending_approvals_count=pending_approvals_count
    )

# --- NEW: Recursive Comment Counter ---
def count_all_comments(comments_list):
    """Recursively counts all comments and their replies."""
    count = 0
    if not comments_list:
        return 0
    
    for comment in comments_list:
        count += 1 # Count the comment itself
        if 'replies' in comment and comment['replies']:
            count += count_all_comments(comment['replies']) # Add count of all its replies
    return count
# --- END NEW ---

# --- Custom Jinja2 Filter for JavaScript String Escaping ---
def js_string_filter(s):
    if s is None:
        return ''
    s = str(s)
    s = s.replace('\\', '\\\\')
    s = s.replace("'", "\\'")
    s = s.replace('"', '\\"')
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    return s

def format_date_filter(date_string):
    if not date_string:
        return ""
    try:
        date_obj = datetime.datetime.strptime(date_string, '%Y-%m-%d')
        return date_obj.strftime('%d/%m/%Y')
    except (ValueError, TypeError):
        return date_string
    
def format_full_date_filter(date_string):
    if not date_string:
        return ""
    try:
        date_obj = datetime.datetime.strptime(str(date_string), '%Y-%m-%d')
        day = date_obj.day
        suffix = 'th' if 11 <= day <= 13 else {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
        return date_obj.strftime(f'%-d{suffix} %B %Y')
    except (ValueError, TypeError):
        return date_string

def format_timestamp_filter(timestamp_string):
    if not timestamp_string:
        return ""
    try:
        # Append ' UTC' to signify the timezone and parse with %Z
        if ' UTC' not in timestamp_string:
            timestamp_string += ' UTC'
        date_obj = datetime.datetime.strptime(timestamp_string.split('.')[0] + ' UTC', '%Y-%m-%d %H:%M:%S %Z')
        
        # This will be handled by JavaScript now, so we just return the original string
        return timestamp_string.replace(' UTC','')
    except (ValueError, TypeError):
        return timestamp_string

# NEW: Filter for event datetime formatting with day suffix
def suffix(d):
    return 'th' if 11 <= d <= 13 else {1: 'st', 2: 'nd', 3: 'rd'}.get(d % 10, 'th')

def format_event_datetime_filter(start_dt, end_dt=None):
    if not isinstance(start_dt, datetime.datetime):
        try:
            start_dt = datetime.datetime.strptime(str(start_dt), '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            return start_dt

    day_with_suffix = str(start_dt.day) + suffix(start_dt.day)
    start_str = start_dt.strftime(f'%A, {day_with_suffix} %B %Y at %H:%M')

    if end_dt:
        if not isinstance(end_dt, datetime.datetime):
            try:
                end_dt = datetime.datetime.strptime(str(end_dt), '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                return start_str # Fallback to just start time

        if start_dt.date() == end_dt.date():
            # Same day
            return f"{start_str} to {end_dt.strftime('%H:%M')}"
        else:
            # Different days
            end_day_with_suffix = str(end_dt.day) + suffix(end_dt.day)
            end_str = end_dt.strftime(f'%A, {end_day_with_suffix} %B %Y at %H:%M')
            return f"{start_str} to {end_str}"
    
    return start_str


# NEW: Filter to linkify locations
def linkify_location_filter(location):
    if not location:
        return Markup("")
    if re.search(r'\d', location) and not location.lower().startswith(('http', 'www')):
        return Markup(
            f'<a href="https://www.google.com/maps/search/?api=1&query={quote(location)}" '
            f'target="_blank" rel="noopener noreferrer" '
            f'class="text-blue-600 dark:text-blue-400 hover:underline">{escape(location)}</a>'
        )
    return linkify_urls(location)


app.jinja_env.filters['js_string'] = js_string_filter
app.jinja_env.filters['linkify_mentions'] = linkify_mentions
app.jinja_env.filters['linkify_urls'] = linkify_urls
app.jinja_env.filters['linkify_everyone_mention'] = linkify_everyone_mention
app.jinja_env.filters['format_date'] = format_date_filter
app.jinja_env.filters['format_full_date'] = format_full_date_filter
app.jinja_env.filters['format_timestamp'] = format_timestamp_filter
# NEW: Register the comment count filter
app.jinja_env.filters['count_all_comments'] = count_all_comments
app.jinja_env.filters['format_event_datetime'] = format_event_datetime_filter
app.jinja_env.filters['linkify_location'] = linkify_location_filter


# --- CIRCULAR IMPORT FIX ---
# Import route blueprints just before registration to avoid circular dependencies
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.main import main_bp
from routes.friends import friends_bp
from routes.comments import comments_bp
from routes.notifications import notifications_bp
from routes.federation import federation_bp
# NEW: Import the groups blueprint
from routes.groups import groups_bp
# NEW: Import the settings blueprint
from routes.settings import settings_bp
# NEW: Import the events blueprint
from routes.events import events_bp
from routes.discovery_filters import discovery_filters_bp
from routes.polls import polls_bp
from routes.two_factor import two_factor_bp

# Register blueprints
app.register_blueprint(admin_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(friends_bp, url_prefix='/friends')
app.register_blueprint(comments_bp)
app.register_blueprint(notifications_bp)
app.register_blueprint(push_notifications_bp)
app.register_blueprint(federation_bp)
# NEW: Register the groups blueprint
app.register_blueprint(groups_bp, url_prefix='/group')
# NEW: Register the settings blueprint
app.register_blueprint(settings_bp, url_prefix='/settings')
# NEW: Register the events blueprint
app.register_blueprint(events_bp)
app.register_blueprint(discovery_filters_bp)
app.register_blueprint(polls_bp)
app.register_blueprint(two_factor_bp)
app.register_blueprint(parental_bp)
app.register_blueprint(shortcuts_bp)
app.register_blueprint(conversations_bp, url_prefix='/conversations')

@app.route('/offline')
def offline():
    """Offline fallback page for PWA"""
    return render_template('offline.html')

@app.after_request
def add_response_headers(response):
    """Cache headers for static files, plus baseline security headers."""
    if request.path.startswith('/static/'):
        # Cache static files for 1 week
        response.headers['Cache-Control'] = 'public, max-age=604800'

    # Baseline security headers. setdefault() means any route that has
    # deliberately set its own value keeps it.
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    return response

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')