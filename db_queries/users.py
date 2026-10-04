# db_queries/users.py
# Contains functions for managing users.

import logging

logger = logging.getLogger(__name__)

import uuid
import sqlite3
from datetime import datetime # Import datetime
from db import get_db
# SECURITY: password hashing lives in one place now. These three functions used
# to inline hashlib.sha256() themselves, which meant fixing utils/auth.py alone
# would have left registration and password resets still writing weak hashes.
from utils.auth import hash_password

# BUG FIX: Explicitly list all columns to ensure all data is fetched,
# especially the 'profile_picture_path' and 'original_profile_picture_path'.
# Using 'SELECT *' can sometimes be unreliable if the table schema changes
# or in certain database configurations.
# MODIFICATION: Add the new 'email' column to the list of columns to be fetched.
USER_COLUMNS = "id, puid, username, password, email, display_name, user_type, hostname, password_must_change, media_path, uploads_path, profile_picture_path, original_profile_picture_path, cover_picture_path, auth_provider, auth_sub"

def get_user_by_username(username):
    """
    Retrieves a LOCAL user by username.
    It specifically checks for users where hostname is NULL.
    """
    db = get_db()
    cursor = db.cursor()
    try:
        # We specify `hostname IS NULL` to ensure we only get local users.
        query = f"SELECT {USER_COLUMNS} FROM users WHERE username = ? AND hostname IS NULL"
        cursor.execute(query, (username,))
        row = cursor.fetchone()
        return dict(row) if row else None
    except sqlite3.OperationalError as e:
        print(f"Database error in get_user_by_username for '{username}': {e}")
        return None

def get_user_by_id(user_id):
    """Retrieves any user (local or remote) by their unique ID."""
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT {USER_COLUMNS} FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    row = cursor.fetchone()
    # BUG FIX: The fetched row is a sqlite3.Row object, not a dictionary.
    # It must be converted to a dictionary before being returned so that
    # other parts of the application can access its data using .get().
    return dict(row) if row else None

def get_user_by_puid(puid):
    """Retrieves any user (local or remote) by their Public User ID."""
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT {USER_COLUMNS} FROM users WHERE puid = ?"
    cursor.execute(query, (puid,))
    row = cursor.fetchone()
    return dict(row) if row else None

def get_user_id_by_username(username):
    """Retrieves a LOCAL user's ID by username."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ? AND hostname IS NULL", (username,))
    result = cursor.fetchone()
    return result['id'] if result else None

def get_username_by_id(user_id):
    """Retrieves a user's username by ID."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    return result['username'] if result else None

def get_user_by_email(email):
    """Retrieves a LOCAL user by their email address."""
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT {USER_COLUMNS} FROM users WHERE email = ? AND hostname IS NULL"
    cursor.execute(query, (email,))
    row = cursor.fetchone()
    return dict(row) if row else None

def get_admin_user():
    """Retrieves the admin user's data from the users table."""
    db = get_db()
    cursor = db.cursor()
    # MODIFICATION: Also retrieve the admin's email address.
    cursor.execute("SELECT id, username, display_name, email FROM users WHERE user_type = 'admin' LIMIT 1")
    row = cursor.fetchone()
    return dict(row) if row else None

def get_admin_by_username(username):
    """Retrieves an admin by username from the users table."""
    db = get_db()
    cursor = db.cursor()
    # BUG FIX: Explicitly select all columns here as well for consistency.
    query = f"SELECT {USER_COLUMNS} FROM users WHERE username = ? AND user_type = 'admin'"
    cursor.execute(query, (username,))
    row = cursor.fetchone()
    return dict(row) if row else None

def add_user(username, password, display_name, user_type='user'):
    """Adds a new LOCAL user to the database."""
    db = get_db()
    hashed_password = hash_password(password)
    puid = str(uuid.uuid4())
    try:
        cursor = db.cursor()
        # MODIFICATION: Also insert the username into the 'email' column.
        cursor.execute("""
            INSERT INTO users (puid, username, email, password, display_name, user_type, hostname)
            VALUES (?, ?, ?, ?, ?, ?, NULL)
        """, (puid, username, username, hashed_password, display_name, user_type))
        user_id = cursor.lastrowid

        # Also initialize default profile info fields for the new user
        default_profile_fields = ['dob', 'hometown', 'occupation', 'bio', 'show_username']
        for field_name in default_profile_fields:
            db.execute("INSERT INTO user_profile_info (user_id, field_name, field_value, privacy_public, privacy_local, privacy_friends) VALUES (?, ?, NULL, 0, 0, 0)", (user_id, field_name))

        db.commit()
        return True
    except sqlite3.IntegrityError: # Username already exists
        return False

def update_user_password(username, new_password):
    """Updates a user's password."""
    db = get_db()
    hashed_password = hash_password(new_password)
    cursor = db.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
    db.commit()
    return cursor.rowcount > 0

def update_user_password_by_id(user_id, new_password):
    """Updates a user's password by their ID."""
    db = get_db()
    hashed_password = hash_password(new_password)
    cursor = db.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
    db.commit()
    return cursor.rowcount > 0

def clear_password_must_change(user_id):
    """Clears the password_must_change flag for a user."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET password_must_change = FALSE WHERE id = ?", (user_id,))
    db.commit()
    return cursor.rowcount > 0

def update_username(user_id, new_username):
    """Updates a user's username (email)."""
    db = get_db()
    cursor = db.cursor()
    # Check if new username is already taken by another local user
    cursor.execute("SELECT id FROM users WHERE username = ? AND hostname IS NULL", (new_username,))
    existing_user = cursor.fetchone()
    if existing_user and existing_user['id'] != user_id:
        return False, "Username already exists."

    try:
        # MODIFICATION: Also update the 'email' column to keep it in sync with the username.
        cursor.execute("UPDATE users SET username = ?, email = ? WHERE id = ?", (new_username, new_username, user_id))
        db.commit()
        return cursor.rowcount > 0, "Username updated successfully."
    except sqlite3.Error as e:
        db.rollback()
        print(f"Error updating username: {e}")
        return False, "A database error occurred."

def update_admin_email(admin_user_id, email):
    """Updates the email address for the admin user."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE users SET email = ? WHERE id = ? AND user_type = 'admin'", (email, admin_user_id))
        db.commit()
        return True
    except sqlite3.Error as e:
        print(f"Error updating admin email: {e}")
        db.rollback()
        return False

def update_user_profile_picture_path(puid, profile_picture_path, original_profile_picture_path=None):
    """
    Updates a user's profile picture path (cropped version) and optionally
    their original profile picture path.
    NEW: Triggers a federation update if a local user changes their picture.
    """
    # Import locally to avoid circular dependencies
    from utils.federation_utils import distribute_profile_update

    db = get_db()
    cursor = db.cursor()
    
    # Get the user's current data *before* the update
    user = get_user_by_puid(puid)
    if not user:
        return False

    try:
        if original_profile_picture_path is not None:
            cursor.execute("UPDATE users SET profile_picture_path = ?, original_profile_picture_path = ? WHERE puid = ?",
                           (profile_picture_path, original_profile_picture_path, puid))
        else:
            cursor.execute("UPDATE users SET profile_picture_path = ?, original_profile_picture_path = NULL WHERE puid = ?",
                           (profile_picture_path, puid))
        
        if cursor.rowcount > 0:
            db.commit()
            # Check if the user is local (hostname is None) before distributing
            if user.get('hostname') is None:
                # We pass the user's PUID, their *existing* display name, and the *new* profile picture path
                distribute_profile_update(
                    puid=puid,
                    display_name=user['display_name'], # The display name hasn't changed in this function
                    profile_picture_path=profile_picture_path # The new picture path
                )
            return True
        else:
            db.rollback() # No rows were updated
            return False
    except Exception as e:
        print(f"Error in update_user_profile_picture_path: {e}")
        db.rollback()
        return False

def update_user_cover_picture_path(puid, cover_picture_path):
    """
    Updates a user's cover/banner picture path.
    Cover photos are local-only and are NOT federated — remote nodes have
    no use for a cover image since they don't render the profile page.
    """
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "UPDATE users SET cover_picture_path = ? WHERE puid = ? AND hostname IS NULL",
            (cover_picture_path, puid)
        )
        if cursor.rowcount > 0:
            db.commit()
            return True
        else:
            db.rollback()
            return False
    except Exception as e:
        print(f"Error in update_user_cover_picture_path: {e}")
        db.rollback()
        return False

# Shown in place of a deleted account's name, everywhere their content appears.
DELETED_USER_DISPLAY_NAME = 'Deleted User'


def delete_user(username):
    """
    Removes a person from the node without destroying what they contributed.

    Nebulae deliberately does NOT cascade-delete a user's content. Posts,
    comments, group history and events they created stay in place and render
    as "Deleted User", because a group or page can remain useful to everyone
    else long after one member leaves. A group admin can still remove any
    individual post if it becomes a problem.

    What this DOES remove is everything personally identifying: email address,
    password, profile and cover pictures, media paths, two-factor secrets,
    active sessions, push subscriptions, saved settings, profile fields and
    shortcuts. The row itself is kept so that every foreign key referencing
    this person stays intact - the alternative, rewriting content to point at
    a shared tombstone account, risks corrupting exactly the history we are
    trying to preserve.

    Setting user_type to 'deleted' also drops them out of mention lookups,
    discovery and search automatically, since those filter on specific types.

    Returns True if a user was anonymised.
    """
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, puid, user_type FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        return False

    user_id = row['id']

    try:
        # A username must stay unique, so replace rather than blank it.
        placeholder_username = f"deleted-{row['puid']}"

        cursor.execute("""
            UPDATE users SET
                username = ?,
                password = '',
                email = NULL,
                display_name = ?,
                media_path = NULL,
                uploads_path = NULL,
                profile_picture_path = NULL,
                original_profile_picture_path = NULL,
                cover_picture_path = NULL,
                user_type = 'deleted',
                password_must_change = 0,
                requires_parental_approval = 0
            WHERE id = ?
        """, (placeholder_username, DELETED_USER_DISPLAY_NAME, user_id))

        # Personal data with no value to anyone else.
        for table in ('user_sessions', 'push_subscriptions', 'user_2fa',
                      'user_settings', 'user_profile_info', 'user_shortcuts',
                      'hidden_content', 'hidden_items', 'pairing_tokens'):
            try:
                cursor.execute(f"DELETE FROM {table} WHERE user_id = ?", (user_id,))
            except sqlite3.OperationalError:
                # Table uses a different column name, or does not exist yet.
                pass

        # Relationships are two-sided; leaving them would show a deleted
        # account in other people's friends lists.
        cursor.execute("DELETE FROM friends WHERE user_id_1 = ? OR user_id_2 = ?", (user_id, user_id))
        cursor.execute("DELETE FROM friend_requests WHERE sender_id = ? OR receiver_id = ?", (user_id, user_id))
        cursor.execute("DELETE FROM friend_relationships WHERE user_id = ? OR friend_id = ?", (user_id, user_id))
        cursor.execute("DELETE FROM followers WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM family_relationships WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM parental_controls WHERE child_user_id = ? OR parent_user_id = ?", (user_id, user_id))
        cursor.execute("DELETE FROM parental_approval_queue WHERE child_user_id = ?", (user_id,))

        # Notifications aimed at them, and notifications about their actions.
        cursor.execute("DELETE FROM notifications WHERE user_id = ? OR actor_id = ?", (user_id, user_id))

        # Hand over any group they were the sole admin of, so it does not
        # become unmanageable. The node admin can reassign it afterwards.
        reassigned = _reassign_orphaned_group_admin(cursor, user_id)

        # Their group membership goes; their posts in the group stay.
        cursor.execute("DELETE FROM group_members WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM group_join_requests WHERE user_id = ?", (user_id,))

        db.commit()
        if reassigned:
            logger.info("delete_user: reassigned %d group(s) to the admin account "
                        "after anonymising %s", reassigned, username)
        return True
    except Exception as e:
        db.rollback()
        logger.error("Error anonymising user %s: %s", username, e)
        return False


def _reassign_orphaned_group_admin(cursor, user_id):
    """
    Promotes the node admin to group admin for any group this user was the
    only admin of. Returns how many groups were reassigned.

    Events are deliberately left alone: an event keeps its original creator
    and simply shows as created by "Deleted User", which is almost always a
    past event nobody needs to manage.
    """
    cursor.execute("SELECT id FROM users WHERE user_type = 'admin' AND hostname IS NULL LIMIT 1")
    admin_row = cursor.fetchone()
    if not admin_row:
        return 0
    admin_id = admin_row['id']
    if admin_id == user_id:
        return 0

    cursor.execute("""
        SELECT group_id FROM group_members
        WHERE user_id = ? AND role = 'admin'
    """, (user_id,))
    group_ids = [r['group_id'] for r in cursor.fetchall()]

    reassigned = 0
    for group_id in group_ids:
        cursor.execute("""
            SELECT COUNT(*) AS n FROM group_members
            WHERE group_id = ? AND role = 'admin' AND user_id != ?
        """, (group_id, user_id))
        if cursor.fetchone()['n'] > 0:
            continue  # someone else can still administer it

        cursor.execute("SELECT id, role FROM group_members WHERE group_id = ? AND user_id = ?",
                       (group_id, admin_id))
        existing = cursor.fetchone()
        if existing:
            cursor.execute("UPDATE group_members SET role = 'admin' WHERE id = ?", (existing['id'],))
        else:
            cursor.execute("INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, 'admin')",
                           (group_id, admin_id))
        reassigned += 1

    return reassigned

def get_all_users_with_media_paths():
    """
    Retrieves all users (local, admin, and remote) to be used for @mention linking.
    This is a critical function for ensuring federated mentions work correctly.
    """
    db = get_db()
    cursor = db.cursor()
    # BUG FIX: Include 'public_page' in the user types to be fetched for mentions.
    query = f"SELECT {USER_COLUMNS} FROM users WHERE user_type IN ('user', 'admin', 'remote', 'public_page') ORDER BY username"
    cursor.execute(query)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def get_all_local_users(include_deleted=False):
    """
    Retrieves all local users (user and admin types) for management purposes.
    It specifically checks for users where hostname is NULL.

    Removed accounts are kept in the table so their posts and comments stay
    readable, but they are noise on an admin screen, so they are hidden unless
    include_deleted is True.
    """
    db = get_db()
    cursor = db.cursor()
    if include_deleted:
        query = f"SELECT {USER_COLUMNS} FROM users WHERE hostname IS NULL ORDER BY username"
    else:
        query = (f"SELECT {USER_COLUMNS} FROM users "
                 f"WHERE hostname IS NULL AND user_type != 'deleted' ORDER BY username")
    cursor.execute(query)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def count_deleted_local_users():
    """How many removed accounts are hidden from the admin user list."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) AS n FROM users WHERE hostname IS NULL AND user_type = 'deleted'")
    row = cursor.fetchone()
    return row['n'] if row else 0

# --- NEW FUNCTION for Searching Discoverable Users ---
def search_discoverable_local_users(search_term, current_user_id):
    """
    Searches for local discoverable users (user or public_page type) by username or display_name,
    excluding the current user, the admin account, and already related users (friends/followed).
    """
    from .friends import get_friendship_status
    from .followers import is_following

    db = get_db()
    cursor = db.cursor()
    search_pattern = f"%{search_term}%"

    cursor.execute(f"""
        SELECT {USER_COLUMNS}
        FROM users
        WHERE user_type IN ('user', 'public_page')
          AND hostname IS NULL
          AND username != 'admin'
          AND id != ?
          AND (username LIKE ? OR display_name LIKE ?)
    """, (current_user_id, search_pattern, search_pattern))

    potential_users = [dict(row) for row in cursor.fetchall()]

    discoverable_users = []
    for profile in potential_users:
        is_related = False
        if profile['user_type'] == 'user':
            friendship_status_result = get_friendship_status(current_user_id, profile['id'])
            friendship_status = friendship_status_result[0] if isinstance(friendship_status_result, tuple) else friendship_status_result
            if friendship_status != 'not_friends':
                is_related = True
        elif profile['user_type'] == 'public_page':
            if is_following(current_user_id, profile['id']):
                is_related = True

        if not is_related:
            discoverable_users.append(profile)

    return discoverable_users
# --- END NEW FUNCTION ---

def get_all_public_pages():
    """Retrieves all local users with the 'public_page' type."""
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT {USER_COLUMNS} FROM users WHERE user_type = 'public_page' AND hostname IS NULL ORDER BY username"
    cursor.execute(query)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def update_user_media_paths(username, media_path, uploads_path):
    """Updates both media_path and uploads_path for a user."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "UPDATE users SET media_path = ?, uploads_path = ? WHERE username = ? AND hostname IS NULL",
            (media_path, uploads_path, username)
        )
        db.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"Database error updating media paths for '{username}': {e}")
        return False

def update_user_media_path(username, media_path):
    """Legacy function - updates only media_path (for backward compatibility)."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "UPDATE users SET media_path = ? WHERE username = ? AND hostname IS NULL",
            (media_path, username)
        )
        db.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"Database error updating media path for '{username}': {e}")
        return False

def update_user_display_name(user_id, display_name):
    """
    Updates a user's display name.
    NEW: Triggers a federation update if a local user changes their name.
    """
    # Import locally to avoid circular dependencies
    from utils.federation_utils import distribute_profile_update
    
    db = get_db()
    cursor = db.cursor()

    # Get the user's current data *before* the update
    user = get_user_by_id(user_id)
    if not user:
        return False
    
    try:
        cursor.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id))
        
        if cursor.rowcount > 0:
            db.commit()
            # Check if the user is local (hostname is None) before distributing
            if user.get('hostname') is None:
                # We pass the user's PUID, the *new* display name, and their *existing* profile picture path
                distribute_profile_update(
                    puid=user['puid'],
                    display_name=display_name, # The new display name
                    profile_picture_path=user['profile_picture_path'] # The existing picture path
                )
            return True
        else:
            db.rollback() # No rows were updated
            return False
    except Exception as e:
        print(f"Error in update_user_display_name: {e}")
        db.rollback()
        return False

def update_remote_user_details(puid, display_name, profile_picture_path):
    """
    Updates the display name and profile picture for a remote user.
    This is used when a friend request is accepted and the remote node sends back the user's details.
    """
    if not puid:
        return False
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            """
            UPDATE users
            SET display_name = ?, profile_picture_path = ?
            WHERE puid = ? AND hostname IS NOT NULL
            """,
            (display_name, profile_picture_path, puid)
        )
        db.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Error updating remote user details for PUID {puid}: {e}")
        return False

# --- NEW: Session Management Functions ---

def create_user_session(user_id, session_id, user_agent, ip_address):
    """Creates a new session record for a user."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""
            INSERT INTO user_sessions (user_id, session_id, user_agent, ip_address)
            VALUES (?, ?, ?, ?)
        """, (user_id, session_id, user_agent, ip_address))
        db.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database error in create_user_session: {e}")
        db.rollback()
        return False

def get_user_sessions(user_id):
    """Retrieves all active sessions for a user."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user_sessions WHERE user_id = ? ORDER BY last_seen DESC", (user_id,))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def get_session_by_id(session_id):
    """Retrieves a session by its unique session ID."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user_sessions WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    return dict(row) if row else None

def update_session_last_seen(session_id):
    """Updates the last_seen timestamp for a session."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE user_sessions SET last_seen = ? WHERE session_id = ?", (datetime.utcnow(), session_id))
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error in update_session_last_seen: {e}")
        db.rollback()

def delete_session_by_id(session_id, user_id):
    """Deletes a specific session for a user, ensuring ownership."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM user_sessions WHERE session_id = ? AND user_id = ?", (session_id, user_id))
        db.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"Database error in delete_session_by_id: {e}")
        db.rollback()
        return False

def delete_all_sessions_for_user(user_id, exclude_session_id=None):
    """Deletes all sessions for a user, optionally excluding the current one."""
    db = get_db()
    cursor = db.cursor()
    try:
        if exclude_session_id:
            cursor.execute("DELETE FROM user_sessions WHERE user_id = ? AND session_id != ?", (user_id, exclude_session_id))
        else:
            cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        db.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database error in delete_all_sessions_for_user: {e}")
        db.rollback()
        return False

# --- Single Sign-On (SSO) Support Functions ---

def get_user_by_auth_sub(auth_sub):
    """Retrieves a local user by their SSO subject identifier."""
    if not auth_sub:
        return None
    db = get_db()
    cursor = db.cursor()
    try:
        query = f"SELECT {USER_COLUMNS} FROM users WHERE auth_sub = ? AND hostname IS NULL"
        cursor.execute(query, (str(auth_sub),))
        row = cursor.fetchone()
        return dict(row) if row else None
    except sqlite3.OperationalError as e:
        logger.warning(f"Database error in get_user_by_auth_sub for '{auth_sub}': {e}")
        return None

def add_sso_user(username, email=None, display_name=None, user_type='user', auth_provider='oidc', auth_sub=None):
    """Adds a new SSO user to the database (password is NULL, local account)."""
    db = get_db()
    puid = str(uuid.uuid4())
    display = display_name or username
    email_addr = email or username
    try:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO users (puid, username, email, password, display_name, user_type, hostname, auth_provider, auth_sub)
            VALUES (?, ?, ?, NULL, ?, ?, NULL, ?, ?)
        """, (puid, username, email_addr, display, user_type, auth_provider, str(auth_sub) if auth_sub else None))
        user_id = cursor.lastrowid

        default_profile_fields = ['dob', 'hometown', 'occupation', 'bio', 'show_username']
        for field_name in default_profile_fields:
            db.execute(
                "INSERT INTO user_profile_info (user_id, field_name, field_value, privacy_public, privacy_local, privacy_friends) VALUES (?, ?, NULL, 0, 0, 0)",
                (user_id, field_name)
            )

        db.commit()
        return True
    except sqlite3.IntegrityError as e:
        logger.warning(f"Integrity error creating SSO user '{username}': {e}")
        return False

def link_user_to_sso(user_id, auth_provider, auth_sub):
    """Links an existing local user account to an SSO identity."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "UPDATE users SET auth_provider = ?, auth_sub = ? WHERE id = ? AND hostname IS NULL",
            (auth_provider, str(auth_sub) if auth_sub else None, user_id)
        )
        db.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        logger.error(f"Error linking user {user_id} to SSO: {e}")
        db.rollback()
        return False

def update_user_role(user_id, user_type):
    """Updates a user's role ('admin' or 'user')."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE users SET user_type = ? WHERE id = ? AND hostname IS NULL", (user_type, user_id))
        db.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        logger.error(f"Error updating role for user {user_id}: {e}")
        db.rollback()
        return False

def update_user_sso_info(user_id, display_name=None, email=None):
    """Updates display name and/or email for an SSO user."""
    db = get_db()
    cursor = db.cursor()
    updates = []
    params = []
    if display_name:
        updates.append("display_name = ?")
        params.append(display_name)
    if email:
        updates.append("email = ?")
        params.append(email)
    if not updates:
        return False
    params.append(user_id)
    try:
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ? AND hostname IS NULL"
        cursor.execute(query, tuple(params))
        db.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        logger.error(f"Error updating SSO info for user {user_id}: {e}")
        db.rollback()
        return False