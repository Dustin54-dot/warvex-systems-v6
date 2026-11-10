-- WARVEX SYSTEMS V6
-- Migration 0004: one-time primary-owner bootstrap.
-- The raw bootstrap code is never stored in D1; only its SHA-256 hash is stored.

CREATE TABLE IF NOT EXISTS owner_bootstrap_tokens (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL COLLATE NOCASE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_primary_owner
  ON owner_accounts(role)
  WHERE role = 'primary_owner' AND status = 'active';
