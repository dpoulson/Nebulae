# routes/settings.py
# Contains routes for managing user settings.

import logging

logger = logging.getLogger(__name__)

from flask import Blueprint, request, jsonify, session, redirect, url_for, flash
from db_queries.users import (get_user_id_by_username, get_user_by_username, 
                              update_user_password_by_id, update_username,
                              get_user_sessions, delete_session_by_id,
                              delete_all_sessions_for_user, get_session_by_id)
from db_queries.settings import update_user_setting
from utils.auth import check_password
from utils.password_validation import validate_password

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/update_settings', methods=['POST'])
def update_settings():
    """
    API endpoint to update one or more settings for the logged-in user.
    Expects a JSON payload with key-value pairs of settings.
    """
    if 'username' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    user_id = get_user_id_by_username(session['username'])
    if not user_id:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400
        
    try:
        # Whitelist of all allowed user settings
        allowed_keys = [
            'text_size', 'timezone', 'theme', 'user_email_address',
            'email_notifications_enabled', 'email_on_friend_request',
            'email_on_friend_accept', 'email_on_wall_post', 'email_on_mention',
            'email_on_event_invite', 'email_on_event_update',
            'email_on_media_tag', 'email_on_media_comment',
            'email_on_post_tag', 'email_on_media_mention'
        ]
        for key, value in data.items():
            if key in allowed_keys:
                # Convert boolean values to strings 'True'/'False' for DB consistency
                if isinstance(value, bool):
                    setting_value = str(value)
                else:
                    setting_value = value
                update_user_setting(user_id, key, setting_value)
        
        return jsonify({'message': 'Settings updated successfully'}), 200
    except Exception as e:
        logger.error(f"Error updating settings for user {user_id}: {e}")
        return jsonify({'error': 'An internal error occurred while updating settings.'}), 500

@settings_bp.route('/update_account', methods=['POST'])
def update_account_credentials():
    """
    API endpoint to update the logged-in user's username and/or password.
    """
    if 'username' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    current_username = session['username']
    user = get_user_by_username(current_username)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400

    current_password = data.get('current_password')
    new_username = data.get('username')
    new_password = data.get('password')

    if user.get('auth_provider') and user.get('auth_provider') != 'local':
        return jsonify({'error': 'Account credentials are managed by your SSO identity provider.'}), 400

    if not check_password(user['password'], current_password):
        return jsonify({'error': 'The current password you entered is incorrect.'}), 403

    relogin_needed = False
    
    # Update username if it has changed
    if new_username and new_username != current_username:
        success, message = update_username(user['id'], new_username)
        if not success:
            return jsonify({'error': message}), 400
        session['username'] = new_username # Update session immediately
        relogin_needed = True

    # Update password if a new one is provided
    if new_password:
        # Validate password against security requirements
        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            return jsonify({'error': error_message}), 400
        update_user_password_by_id(user['id'], new_password)
        relogin_needed = True
        
    if relogin_needed:
        message = 'Account updated successfully! Please log in again with your new credentials.'
    else:
        message = 'No changes detected.'

    return jsonify({'message': message, 'relogin': relogin_needed}), 200

@settings_bp.route('/get_sessions', methods=['GET'])
def get_sessions():
    """API endpoint to get all active sessions for the logged-in user."""
    if 'username' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    user = get_user_by_username(session['username'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    sessions = get_user_sessions(user['id'])
    current_session_id = session.get('session_id')
    
    for s in sessions:
        s['is_current'] = (s['session_id'] == current_session_id)

    return jsonify(sessions)

@settings_bp.route('/logout_session/<session_id>', methods=['POST'])
def logout_session(session_id):
    """API endpoint to log out a specific session."""
    if 'username' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    user = get_user_by_username(session['username'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    target_session = get_session_by_id(session_id)
    if not target_session or target_session['user_id'] != user['id']:
        return jsonify({'error': 'Session not found or you do not have permission to log it out.'}), 404
    
    if delete_session_by_id(session_id, user['id']):
        if session_id == session.get('session_id'):
            session.clear()
            return jsonify({'message': 'Successfully logged out of the current session.', 'logout_self': True})
        return jsonify({'message': 'Session logged out successfully.'})
    else:
        return jsonify({'error': 'Failed to log out session.'}), 500

@settings_bp.route('/logout_all_sessions', methods=['POST'])
def logout_all_sessions():
    """API endpoint to log out all sessions except the current one."""
    if 'username' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    user = get_user_by_username(session['username'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    current_session_id = session.get('session_id')
    if not current_session_id:
        return jsonify({'error': 'Current session ID not found.'}), 400
    
    if delete_all_sessions_for_user(user['id'], exclude_session_id=current_session_id):
        return jsonify({'message': 'All other sessions have been logged out.'})
    else:
        return jsonify({'error': 'Failed to log out other sessions.'}), 500

