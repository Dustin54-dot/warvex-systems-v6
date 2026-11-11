CREATE TABLE IF NOT EXISTS app_notifications (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  read_at INTEGER,
  event_key TEXT NOT NULL,
  FOREIGN KEY(account_id) REFERENCES app_accounts(id),
  UNIQUE(account_id,event_key)
);
CREATE INDEX IF NOT EXISTS idx_app_notifications_account_created
  ON app_notifications(account_id, created_at DESC);
