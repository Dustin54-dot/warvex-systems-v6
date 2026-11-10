-- WARVEX SYSTEMS V6
-- Migration 0005: limit repeated OWNER password guesses per challenge.

ALTER TABLE owner_challenges ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE owner_challenges ADD COLUMN locked_until INTEGER;
