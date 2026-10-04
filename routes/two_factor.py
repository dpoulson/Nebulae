# routes/two_factor.py
from flask import Blueprint, request, session, jsonify
import pyotp
import qrcode
import io
import base64
from db_queries.users import get_user_by_username
from db_queries.two_factor import (
    get_2fa_settings, create_2fa_secret, enable_2fa, disable_2fa, regenerate_backup_codes
)
from utils.auth import check_password

two_factor_bp = Blueprint('two_factor', __name__)

@two_factor_bp.before_request
def login_required():
    """Ensures a user is logged in before accessing 2FA settings."""
    if 'username' not in session:
        return jsonify({'error': 'Authentication required'}), 401

@two_factor_bp.route('/settings/2fa/status', methods=['GET'])
def get_2fa_status():
    """API endpoint to check if 2FA is enabled for the current user."""
    user = get_user_by_username(session['username'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.get('auth_provider') and user.get('auth_provider') != 'local':
        return jsonify({
            'enabled': False,
            'is_sso': True,
            'message': 'Two-factor authentication is managed by your SSO Identity Provider.'
        })

    twofa_settings = get_2fa_settings(user['id'])
    
    return jsonify({
        'enabled': twofa_settings['enabled'] if twofa_settings else False,
        'is_sso': False
    })

@two_factor_bp.route('/settings/2fa/setup', methods=['POST'])
def setup_2fa():
    """Set up 2FA for the user - returns QR code and backup codes."""
    user = get_user_by_username(session['username'])
    
    data = request.get_json()
    current_password = data.get('current_password')
    
    if user.get('auth_provider') and user.get('auth_provider') != 'local':
        return jsonify({'error': 'Two-factor authentication is managed by your SSO identity provider.'}), 400

    # Verify current password
    if not check_password(user['password'], current_password):
        return jsonify({'error': 'Incorrect password'}), 403
    
    # Generate new secret
    secret = pyotp.random_base32()
    backup_codes = create_2fa_secret(user['id'], secret)
    
    # Store secret in session temporarily for verification
    session['pending_2fa_secret'] = secret
    session['pending_2fa_backup_codes'] = backup_codes
    
    # Generate QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user['username'],
        issuer_name='Nebulae'
    )
    
    # Create QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for embedding
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code_data = base64.b64encode(buf.getvalue()).decode()
    
    return jsonify({
        'qr_code': qr_code_data,
        'secret': secret,
        'backup_codes': backup_codes
    })

@two_factor_bp.route('/settings/2fa/verify', methods=['POST'])
def verify_2fa_setup():
    """Verify 2FA setup with a test code."""
    user = get_user_by_username(session['username'])
    secret = session.get('pending_2fa_secret')
    
    if not secret:
        return jsonify({'error': 'No pending 2FA setup'}), 400
    
    data = request.get_json()
    otp_code = data.get('otp_code')
    
    # Verify the code
    totp = pyotp.TOTP(secret)
    if totp.verify(otp_code, valid_window=1):
        # Enable 2FA
        enable_2fa(user['id'])
        
        # Clear session data
        session.pop('pending_2fa_secret', None)
        backup_codes = session.pop('pending_2fa_backup_codes', [])
        
        return jsonify({
            'success': True, 
            'message': '2FA enabled successfully!',
            'backup_codes': backup_codes
        })
    else:
        return jsonify({'error': 'Invalid code. Please try again.'}), 400

@two_factor_bp.route('/settings/2fa/disable', methods=['POST'])
def disable_2fa_route():
    """Disable 2FA for the user."""
    user = get_user_by_username(session['username'])
    
    data = request.get_json()
    current_password = data.get('current_password')
    otp_code = data.get('otp_code')
    
    if user.get('auth_provider') and user.get('auth_provider') != 'local':
        return jsonify({'error': 'Two-factor authentication is managed by your SSO identity provider.'}), 400

    # Verify password
    if not check_password(user['password'], current_password):
        return jsonify({'error': 'Incorrect password'}), 403
    
    # Verify OTP
    twofa_settings = get_2fa_settings(user['id'])
    if twofa_settings:
        totp = pyotp.TOTP(twofa_settings['secret'])
        if not totp.verify(otp_code, valid_window=1):
            return jsonify({'error': 'Invalid authentication code'}), 403
    
    # Disable 2FA
    disable_2fa(user['id'])
    
    return jsonify({'success': True, 'message': '2FA disabled successfully'})

@two_factor_bp.route('/settings/2fa/regenerate_backup_codes', methods=['POST'])
def regenerate_backup_codes_route():
    """Regenerate backup codes for the user."""
    user = get_user_by_username(session['username'])
    
    data = request.get_json()
    current_password = data.get('current_password')
    otp_code = data.get('otp_code')
    
    # Verify password
    if not check_password(user['password'], current_password):
        return jsonify({'error': 'Incorrect password'}), 403
    
    # Verify OTP
    twofa_settings = get_2fa_settings(user['id'])
    if not twofa_settings or not twofa_settings['enabled']:
        return jsonify({'error': '2FA is not enabled'}), 400
    
    totp = pyotp.TOTP(twofa_settings['secret'])
    if not totp.verify(otp_code, valid_window=1):
        return jsonify({'error': 'Invalid authentication code'}), 403
    
    # Regenerate codes
    new_codes = regenerate_backup_codes(user['id'])
    
    return jsonify({
        'success': True, 
        'message': 'Backup codes regenerated successfully',
        'backup_codes': new_codes
    })