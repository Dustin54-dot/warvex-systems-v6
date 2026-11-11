-- WARVEX SYSTEMS V6
-- Migration 0006: public email/password accounts and server-side roles.
-- Additive only. Existing OWNER accounts and device authentication are untouched.

ALTER TABLE app_accounts
  ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
  CHECK(role IN ('user','team_member','admin'));

CREATE TABLE IF NOT EXISTS app_user_sessions (
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  FOREIGN KEY(account_id) REFERENCES app_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_app_user_sessions_account
  ON app_user_sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_app_user_sessions_expiry
  ON app_user_sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_app_accounts_role_status
  ON app_accounts(role,status);
