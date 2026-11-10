-- WARVEX SYSTEMS V6
-- Migration: allow one account on multiple registered devices,
-- while each device credential can belong to only one account.
-- Apply ONCE to the previous app_account_devices schema.
-- Before applying, create and verify a D1 backup.

CREATE TABLE app_accounts_backup_20261110 AS SELECT * FROM app_accounts;
CREATE TABLE app_account_devices_backup_20261110 AS SELECT * FROM app_account_devices;
CREATE TABLE app_sessions_backup_20261110 AS SELECT * FROM app_sessions;
CREATE TABLE app_auth_challenges_backup_20261110 AS SELECT * FROM app_auth_challenges;

CREATE TABLE app_account_devices_new (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  credential_id_hash TEXT NOT NULL UNIQUE,
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  device_label TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  revoked_at INTEGER,
  FOREIGN KEY(account_id) REFERENCES app_accounts(id)
);

INSERT INTO app_account_devices_new (
  id, account_id, credential_id_hash, public_key, sign_count,
  device_label, created_at, last_seen_at, revoked_at
)
SELECT
  id, account_id, credential_id_hash, public_key, sign_count,
  device_label, created_at, last_seen_at, revoked_at
FROM app_account_devices;

DROP TABLE app_account_devices;
ALTER TABLE app_account_devices_new RENAME TO app_account_devices;

CREATE INDEX idx_app_devices_account
  ON app_account_devices(account_id);

CREATE TABLE app_device_approvals (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  requester_device_hash TEXT NOT NULL UNIQUE,
  requester_label TEXT NOT NULL,
  approval_code_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (
    status IN ('pending','approved','denied','expired','consumed')
  ),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_at INTEGER,
  approved_by_device_id TEXT,
  consumed_at INTEGER,
  FOREIGN KEY(account_id) REFERENCES app_accounts(id),
  FOREIGN KEY(approved_by_device_id) REFERENCES app_account_devices(id)
);

CREATE INDEX idx_app_device_approvals_account_status
  ON app_device_approvals(account_id, status, created_at);
