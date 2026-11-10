-- WARVEX SYSTEMS V6
-- Migration 0003: password credentials, owner sessions and signed device requests.
-- Additive only. Does not delete or rewrite existing account/owner records.

CREATE TABLE IF NOT EXISTS app_account_passwords (
  account_id TEXT PRIMARY KEY,
  salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  iterations INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(account_id) REFERENCES app_accounts(id)
);

ALTER TABLE app_device_approvals ADD COLUMN requester_public_key TEXT;
ALTER TABLE app_device_approvals ADD COLUMN request_token_hash TEXT;

CREATE TABLE IF NOT EXISTS owner_passwords (
  owner_id TEXT PRIMARY KEY,
  salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  iterations INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(owner_id) REFERENCES owner_accounts(id)
);

CREATE TABLE IF NOT EXISTS owner_sessions (
  token_hash TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  FOREIGN KEY(owner_id) REFERENCES owner_accounts(id),
  FOREIGN KEY(device_id) REFERENCES owner_devices(id)
);

CREATE TABLE IF NOT EXISTS owner_challenges (
  id TEXT PRIMARY KEY,
  challenge_hash TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL COLLATE NOCASE,
  purpose TEXT NOT NULL CHECK(purpose IN ('login','device_change')),
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL
);

ALTER TABLE owner_devices ADD COLUMN credential_id_hash TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_owner_devices_credential_hash
  ON owner_devices(credential_id_hash)
  WHERE credential_id_hash IS NOT NULL;

ALTER TABLE owner_access_requests ADD COLUMN credential_public_key TEXT;
ALTER TABLE owner_access_requests ADD COLUMN credential_id_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_owner_requests_email_status
  ON owner_access_requests(email, status, created_at);

CREATE INDEX IF NOT EXISTS idx_owner_sessions_owner
  ON owner_sessions(owner_id);
CREATE INDEX IF NOT EXISTS idx_owner_sessions_expiry
  ON owner_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_owner_challenges_email
  ON owner_challenges(email, purpose);
