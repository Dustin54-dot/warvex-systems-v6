-- WARVEX SYSTEMS V6
-- Migration 0008: account display names and private security reports.
-- Additive only; existing account IDs remain stable.

ALTER TABLE app_accounts ADD COLUMN display_name TEXT;

CREATE TABLE IF NOT EXISTS app_security_reports (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('suspicious_content','possible_threat','security_issue','other')),
  content TEXT NOT NULL,
  district TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','reviewed')),
  created_at INTEGER NOT NULL,
  reviewed_at INTEGER,
  reviewed_by TEXT,
  FOREIGN KEY(account_id) REFERENCES app_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_app_security_reports_status_created
  ON app_security_reports(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_app_security_reports_account
  ON app_security_reports(account_id, created_at DESC);
