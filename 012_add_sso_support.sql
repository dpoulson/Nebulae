-- Migration: Add SSO (OIDC and Reverse Proxy ForwardAuth) support
-- Version: 012
--
-- Adds columns to link local user records to external SSO identity providers (e.g. Authelia)
-- and support passwordless SSO accounts.

ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local';
ALTER TABLE users ADD COLUMN auth_sub TEXT;

CREATE INDEX IF NOT EXISTS idx_users_auth_sub ON users(auth_sub);
CREATE INDEX IF NOT EXISTS idx_users_auth_provider ON users(auth_provider);
