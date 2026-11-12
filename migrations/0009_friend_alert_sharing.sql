-- WARVEX SYSTEMS V6 · Migration 0009
-- Account-based friend requests and explicit critical-pulse sharing.
CREATE TABLE IF NOT EXISTS app_friend_requests (
  id TEXT PRIMARY KEY,
  requester_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected')),
  created_at INTEGER NOT NULL,
  responded_at INTEGER,
  CHECK(requester_id <> recipient_id),
  FOREIGN KEY(requester_id) REFERENCES app_accounts(id),
  FOREIGN KEY(recipient_id) REFERENCES app_accounts(id),
  UNIQUE(requester_id,recipient_id)
);
CREATE INDEX IF NOT EXISTS idx_app_friend_requests_recipient_status
  ON app_friend_requests(recipient_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_app_friend_requests_requester_status
  ON app_friend_requests(requester_id,status,created_at DESC);

CREATE TABLE IF NOT EXISTS app_friend_shares (
  sender_id TEXT NOT NULL,
  receiver_id TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
  last_alert_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(sender_id,receiver_id),
  FOREIGN KEY(sender_id) REFERENCES app_accounts(id),
  FOREIGN KEY(receiver_id) REFERENCES app_accounts(id)
);
CREATE INDEX IF NOT EXISTS idx_app_friend_shares_receiver
  ON app_friend_shares(receiver_id,enabled);
