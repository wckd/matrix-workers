-- Migration 012: Add redaction tracking and device_keys table
-- Required for proper redaction content stripping per Matrix spec
-- and device key cleanup on device deletion

-- Add redacted_because column to track which event redacted this one
ALTER TABLE events ADD COLUMN redacted_because TEXT;

-- Index for finding redacted events
CREATE INDEX IF NOT EXISTS idx_events_redacted ON events(redacted_because) WHERE redacted_because IS NOT NULL;

-- Device keys table for E2EE
-- Primary storage is in Durable Objects/KV, this is for cleanup operations
CREATE TABLE IF NOT EXISTS device_keys (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_data TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    PRIMARY KEY (user_id, device_id, algorithm, key_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_device_keys_user_device ON device_keys(user_id, device_id);
