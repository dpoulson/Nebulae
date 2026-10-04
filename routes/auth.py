# routes/auth.py
import uuid
import hashlib
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature, BadData
from db_queries.users import (get_user_by_username, create_user_session, delete_session_by_id,
                              get_user_by_email, update_user_password_by_id,
                              delete_all_sessions_for_user)
from utils.auth import check_password, hash_password, is_legacy_hash
from utils.email_utils import send_email
from utils.password_validation import validate_password, get_password_requirements_text
import logging
logger = logging.getLogger(__name__)

from utils.sso import get_oauth_client, login_or_provision_sso_user

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user and admin login with optional 2FA.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp_code = request.form.get('otp_code', '').strip()

        user = get_user_by_username(username)

        # THROTTLE: keyed on the submitted username, whether or not it exists,
        # so a throttled response never reveals which accounts are real.
        wait = throttle.seconds_remaining('login', username)
        if wait:
            flash(f'Too many failed attempts. Please try again in {throttle.describe_wait(wait)}.', 'danger')
            return render_template('login.html')

        # Check if this is a 2FA verification attempt (from login_2fa.html)
        if otp_code and 'pending_2fa_user_id' in session:
            # User is attempting 2FA verification - skip password check
            from db_queries.two_factor import get_2fa_settings, update_2fa_last_used, verify_backup_code
            import pyotp

            # THROTTLE: exhausting 2FA attempts also drops the pending state, so
            # the attacker has to clear the (throttled) password step again.
            twofa_wait = throttle.seconds_remaining('twofa', username)
            if twofa_wait:
                session.pop('pending_2fa_user_id', None)
                session.pop('pending_2fa_username', None)
                flash(f'Too many incorrect codes. Please sign in again in {throttle.describe_wait(twofa_wait)}.', 'danger')
                return redirect(url_for('auth.login'))

            # BUGFIX: user is None when the submitted username does not exist,
            # which made the comparison below raise TypeError (a 500).
            if not user or session['pending_2fa_user_id'] != user['id']:
                flash('Invalid authentication attempt', 'danger')
                session.pop('pending_2fa_user_id', None)
                session.pop('pending_2fa_username', None)
                return redirect(url_for('auth.login'))
            
            twofa_settings = get_2fa_settings(user['id'])
            
            if twofa_settings and twofa_settings['enabled']:
                # Verify OTP code
                totp = pyotp.TOTP(twofa_settings['secret'])
                
                # Try OTP first, then backup codes
                if totp.verify(otp_code, valid_window=1):
                    update_2fa_last_used(user['id'])
                    # OTP verified - continue to login completion
                elif verify_backup_code(user['id'], otp_code):
                    flash('Backup code used successfully. Consider regenerating backup codes in settings.', 'warning')
                    # Backup code verified - continue to login completion
                else:
                    throttle.record_attempt('twofa', username)
                    flash('Invalid authentication code', 'danger')
                    return render_template('login_2fa.html', username=username)
            
            # Code accepted - release the 2FA throttle for this account.
            throttle.clear('twofa', username)

            # Clear pending 2FA session data
            session.pop('pending_2fa_user_id', None)
            session.pop('pending_2fa_username', None)
            
            # Fall through to login completion below
            
        elif user and check_password(user['password'], password):
            # SECURITY: transparently upgrade legacy unsalted SHA-256 hashes.
            # The plaintext is only available here, at login, so this is the one
            # place the migration can happen. It runs once per user - after the
            # rewrite is_legacy_hash() is False and this branch is skipped.
            if is_legacy_hash(user['password']):
                update_user_password_by_id(user['id'], password)

            # Initial login with valid password
            from db_queries.two_factor import get_2fa_settings
            
            # Check if 2FA is enabled for this user
            twofa_settings = get_2fa_settings(user['id'])
            
            if twofa_settings and twofa_settings['enabled']:
                # 2FA is enabled - require OTP
                session['pending_2fa_user_id'] = user['id']
                session['pending_2fa_username'] = username
                return render_template('login_2fa.html', username=username)
            
            # No 2FA - fall through to login completion below
            
        else:
            # Invalid username or password
            throttle.record_attempt('login', username)
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        
        # Login completion (reached after password check OR successful 2FA)
        throttle.clear('login', username)

        session.clear()
        session['username'] = username
        session['is_admin'] = (user['user_type'] == 'admin')
        
        # Create a new session ID
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id
        session.permanent = True
        
        # Store session in the database
        create_user_session(user['id'], session_id, request.user_agent.string, request.remote_addr)
        
        # Check if user must change password
        if user.get('password_must_change'):
            flash('You must change your password from the default before continuing.', 'warning')
            return redirect(url_for('admin.admin_manage_users', force_password_reset='admin'))
        
        flash('Login successful!', 'success')
        if session['is_admin']:
            return redirect(url_for('admin.admin_dashboard'))
        else:
            return redirect(url_for('main.index'))
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    """
    Logs out the current user or admin.
    """
    session_id = session.get('session_id')
    if session_id:
        user = get_user_by_username(session.get('username'))
        if user:
            delete_session_by_id(session_id, user['id'])

    auth_provider = session.get('auth_provider')
    session.clear()
    flash('You have been logged out.', 'info')

    # If proxy auth logout URL is configured (e.g. Authelia logout)
    proxy_logout = current_app.config.get('PROXY_AUTH_LOGOUT_URL')
    if auth_provider == 'proxy' and proxy_logout:
        return redirect(proxy_logout)

    # If OIDC logout URL is configured
    oidc_logout = current_app.config.get('OIDC_LOGOUT_URL')
    if auth_provider == 'oidc' and oidc_logout:
        return redirect(oidc_logout)

    return redirect(url_for('main.index'))

@auth_bp.route('/auth/oidc/login')
def oidc_login():
    """
    Redirects user to Authelia / OIDC provider authorization endpoint.
    """
    if not current_app.config.get('OIDC_ENABLED'):
        flash('SSO authentication is not enabled.', 'warning')
        return redirect(url_for('auth.login'))

    oauth_client = get_oauth_client()
    if not oauth_client:
        flash('SSO provider client is not configured or unavailable.', 'danger')
        return redirect(url_for('auth.login'))

    redirect_uri = current_app.config.get('OIDC_REDIRECT_URI')
    if not redirect_uri:
        redirect_uri = url_for('auth.oidc_callback', _external=True)
        # Ensure https scheme if behind TLS-terminating reverse proxy
        if request.headers.get('X-Forwarded-Proto') == 'https' and redirect_uri.startswith('http://'):
            redirect_uri = 'https://' + redirect_uri[7:]

    return oauth_client.authorize_redirect(redirect_uri)

@auth_bp.route('/auth/oidc/callback')
def oidc_callback():
    """
    Handles OIDC authorization callback from Authelia.
    Exchanges code for tokens, retrieves user claims, provisions/links user,
    and sets up application session.
    """
    if not current_app.config.get('OIDC_ENABLED'):
        flash('SSO authentication is not enabled.', 'warning')
        return redirect(url_for('auth.login'))

    oauth_client = get_oauth_client()
    if not oauth_client:
        flash('SSO provider client is unavailable.', 'danger')
        return redirect(url_for('auth.login'))

    try:
        token = oauth_client.authorize_access_token()
    except Exception as e:
        logger.error(f"OIDC token exchange failed: {e}")
        flash('Authentication failed or was canceled. Please try again.', 'danger')
        return redirect(url_for('auth.login'))

    user_info = token.get('userinfo')
    if not user_info:
        try:
            user_info = oauth_client.userinfo(token=token)
        except Exception as e:
            logger.error(f"Failed to fetch userinfo from OIDC provider: {e}")
            user_info = {}

    sub = user_info.get('sub')
    username = user_info.get('preferred_username') or user_info.get('username') or user_info.get('nickname')
    email = user_info.get('email')
    display_name = user_info.get('name') or user_info.get('given_name')
    groups = user_info.get('groups') or []

    if not username and email:
        username = email.split('@')[0]
    elif not username and sub:
        username = f"user_{str(sub)[:8]}"

    if not username:
        logger.error("OIDC callback missing user identifier claim.")
        flash('Unable to retrieve user identity from SSO provider.', 'danger')
        return redirect(url_for('auth.login'))

    try:
        admin_group = current_app.config.get('OIDC_ADMIN_GROUP', 'admins')
        user = login_or_provision_sso_user(
            username=username,
            email=email,
            display_name=display_name,
            groups=groups,
            auth_provider='oidc',
            auth_sub=sub,
            admin_group=admin_group
        )
    except Exception as e:
        logger.error(f"Failed to provision or log in SSO user '{username}': {e}")
        flash('An error occurred during SSO sign-in.', 'danger')
        return redirect(url_for('auth.login'))

    flash(f"Welcome, {user['display_name']}!", 'success')
    if session.get('is_admin'):
        return redirect(url_for('admin.admin_dashboard'))
    return redirect(url_for('main.index'))

def _password_fingerprint(password_hash):
    """
    Short digest of the stored password hash, embedded in reset tokens.

    NOTE: this is a fingerprint of an already-hashed value, NOT password
    storage - utils.auth handles that with scrypt. SHA-256 is fine here.

    Binding the token to the hash makes the link single-use: completing a
    reset replaces the hash, so the fingerprint stops matching and the link
    (plus any older outstanding links) immediately stops working.
    """
    return hashlib.sha256((password_hash or '').encode()).hexdigest()[:16]


@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Handles the request to reset a password.
    Sends an email with a time-sensitive token.
    """
    if request.method == 'POST':
        email = request.form.get('email')

        # THROTTLE: reset requests cost outbound email and issue a valid token,
        # so they are capped per address. When capped we fall through silently
        # to the same generic message, which avoids confirming the address.
        reset_wait = throttle.seconds_remaining('reset', email)
        user = None if reset_wait else get_user_by_email(email)
        if not reset_wait:
            throttle.record_attempt('reset', email)

        if user:
            # If the account is an SSO account, skip password reset link
            if user.get('auth_provider') and user.get('auth_provider') != 'local':
                flash('If an account with that email exists, a password reset link has been sent.', 'info')
                return redirect(url_for('auth.login'))

            # Generate a password reset token
            s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            token = s.dumps(
                {'email': user['email'], 'fp': _password_fingerprint(user['password'])},
                salt='password-reset-salt'
            )

            # Create the reset link
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            
            # Send the email
            subject = "Password Reset Request"
            body_html = f"<p>You are receiving this email because a password reset was requested for your account.</p><p>Click the link below to reset your password:</p><p><a href='{reset_url}'>{reset_url}</a></p><p>If you did not request a password reset, please ignore this email.</p>"
            
            send_email(user['email'], subject, body_html)

        # Flash a generic message to prevent user enumeration
        flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('auth.login'))

    return render_template('forgot_password.html')

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Handles the actual password reset using the token.
    """
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        # The token is valid for 1800 seconds (30 minutes)
        data = s.loads(token, salt='password-reset-salt', max_age=1800)
    except SignatureExpired:
        flash('The password reset link has expired. Please request a new one.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    except (BadSignature, BadData):
        # BUGFIX: a malformed or truncated link raises BadSignature, which the
        # previous handler did not catch - it produced a 500 instead of this.
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    # Tokens issued before this change were a bare email string. They are only
    # valid for 30 minutes anyway, so ask for a fresh one rather than honouring
    # a format that has no single-use protection.
    if not isinstance(data, dict):
        flash('The password reset link is invalid or has expired. Please request a new one.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    user = get_user_by_email(data.get('email'))

    # SECURITY: reject a token whose embedded fingerprint no longer matches the
    # stored hash. This is what makes the link single-use, and it is checked on
    # GET too so a spent link never even renders the form.
    if not user or data.get('fp') != _password_fingerprint(user['password']):
        flash('This password reset link is no longer valid. It may already have been used.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        # Validate password against security requirements
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message, 'danger')
            return render_template('reset_password.html', token=token)

        update_user_password_by_id(user['id'], password)

        # SECURITY: a reset is often a response to a compromise, so drop every
        # existing session. Without this, a thief holding a stolen session
        # cookie stays logged in after the legitimate owner resets.
        delete_all_sessions_for_user(user['id'])
        session.clear()

        flash('Your password has been reset successfully. You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)
