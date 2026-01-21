// To-Device Messages API
// Implements: https://spec.matrix.org/v1.12/client-server-api/#send-to-device-messaging
//
// To-device messages are used for:
// - E2E encryption key exchange (m.room_key, m.room_key_request)
// - Device verification (m.key.verification.*)
// - Direct device-to-device communication
//
// Messages are delivered via /sync and sliding sync extensions

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';

const app = new Hono<AppEnv>();

// ============================================
// Types
// ============================================

interface ToDeviceRequest {
  messages: Record<string, Record<string, any>>;
  // messages[user_id][device_id] = content
  // device_id can be "*" to send to all devices
}

// ============================================
// Helper Functions
// ============================================

async function getNextStreamPosition(db: D1Database, streamName: string): Promise<number> {
  // Atomic UPDATE with RETURNING - no race condition
  const result = await db.prepare(`
    UPDATE stream_positions
    SET position = position + 1
    WHERE stream_name = ?
    RETURNING position
  `).bind(streamName).first<{ position: number }>();

  if (result) {
    return result.position;
  }

  // Row doesn't exist - atomic upsert (edge case, should be created by migration)
  const upsertResult = await db.prepare(`
    INSERT INTO stream_positions (stream_name, position)
    VALUES (?, 1)
    ON CONFLICT (stream_name) DO UPDATE SET position = position + 1
    RETURNING position
  `).bind(streamName).first<{ position: number }>();

  return upsertResult?.position ?? 1;
}

async function getUserDevices(db: D1Database, userId: string): Promise<string[]> {
  const devices = await db.prepare(`
    SELECT device_id FROM devices WHERE user_id = ?
  `).bind(userId).all<{ device_id: string }>();

  return devices.results.map(d => d.device_id);
}

// ============================================
// Endpoints
// ============================================

// PUT /sendToDevice/:eventType/:txnId - Send to-device messages
app.put('/_matrix/client/v3/sendToDevice/:eventType/:txnId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const eventType = c.req.param('eventType');
  const txnId = c.req.param('txnId');
  const db = c.env.DB;

  // Check for duplicate transaction
  const existingTxn = await db.prepare(`
    SELECT response FROM transaction_ids WHERE user_id = ? AND txn_id = ?
  `).bind(userId, txnId).first<{ response: string }>();

  if (existingTxn) {
    // Return cached response for idempotency
    return c.json(JSON.parse(existingTxn.response || '{}'));
  }

  let body: ToDeviceRequest;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  if (!body.messages) {
    return Errors.missingParam('messages').toResponse();
  }

  // Process each recipient user
  for (const [recipientUserId, deviceMessages] of Object.entries(body.messages)) {
    // Get list of device IDs to send to
    let targetDevices: string[];

    for (const [deviceId, content] of Object.entries(deviceMessages)) {
      if (deviceId === '*') {
        // Send to all devices for this user
        targetDevices = await getUserDevices(db, recipientUserId);
      } else {
        targetDevices = [deviceId];
      }

      // Create a message for each target device
      for (const targetDeviceId of targetDevices) {
        const streamPosition = await getNextStreamPosition(db, 'to_device');
        const messageId = `${userId}_${txnId}_${recipientUserId}_${targetDeviceId}_${Date.now()}`;

        await db.prepare(`
          INSERT INTO to_device_messages (
            recipient_user_id, recipient_device_id, sender_user_id,
            event_type, content, message_id, stream_position
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT (recipient_user_id, recipient_device_id, message_id) DO NOTHING
        `).bind(
          recipientUserId,
          targetDeviceId,
          userId,
          eventType,
          JSON.stringify(content),
          messageId,
          streamPosition
        ).run();
      }
    }
  }

  // Store transaction for idempotency
  await db.prepare(`
    INSERT INTO transaction_ids (user_id, txn_id, response)
    VALUES (?, ?, '{}')
    ON CONFLICT (user_id, txn_id) DO NOTHING
  `).bind(userId, txnId).run();

  return c.json({});
});

// ============================================
// Internal helper: Get to-device messages for sync
// ============================================

export async function getToDeviceMessages(
  db: D1Database,
  userId: string,
  deviceId: string,
  since?: string,
  limit: number = 100
): Promise<{ events: any[]; nextBatch: string }> {
  // Parse the since token - it's a stream position
  // IMPORTANT: Validate that since is a reasonable stream position (not a timestamp)
  let sincePos = 0;
  if (since) {
    const parsed = parseInt(since);
    // Stream positions should be reasonable numbers (< 1 billion)
    // Timestamps would be > 1 trillion (milliseconds since epoch)
    if (!isNaN(parsed) && parsed > 0 && parsed < 1000000000) {
      sincePos = parsed;
    } else if (parsed >= 1000000000) {
      // This looks like a timestamp, ignore it and treat as first sync
      console.log('[to-device] Ignoring invalid since token (looks like timestamp):', since);
    }
  }

  // STEP 1: Get undelivered messages FIRST (before any acknowledgment)
  // This ensures we have a snapshot of what exists before any modifications
  // and prevents race conditions where messages are marked delivered before being fetched
  const messages = await db.prepare(`
    SELECT id, sender_user_id, event_type, content, stream_position
    FROM to_device_messages
    WHERE recipient_user_id = ?
      AND recipient_device_id = ?
      AND delivered = 0
      AND stream_position > ?
    ORDER BY stream_position ASC
    LIMIT ?
  `).bind(userId, deviceId, sincePos, limit).all<{
    id: number;
    sender_user_id: string;
    event_type: string;
    content: string;
    stream_position: number;
  }>();

  // STEP 2: NOW acknowledge previously sent messages
  // Only acknowledge up to the sincePos the client sent back
  // This means the client has confirmed receipt of everything <= sincePos
  if (sincePos > 0) {
    const ackResult = await db.prepare(`
      UPDATE to_device_messages
      SET delivered = 1
      WHERE recipient_user_id = ?
        AND recipient_device_id = ?
        AND stream_position <= ?
        AND delivered = 0
    `).bind(userId, deviceId, sincePos).run();

    if (ackResult.meta.changes > 0) {
      console.log('[to-device] Acknowledged', ackResult.meta.changes, 'messages up to position', sincePos, 'for', userId, 'device:', deviceId);
    }
  }

  // Debug: Log to-device retrieval
  if (messages.results.length > 0) {
    console.log('[to-device] Returning', messages.results.length, 'messages to', userId, 'device:', deviceId);
    for (const msg of messages.results) {
      console.log('[to-device]   -', msg.event_type, 'from', msg.sender_user_id, 'pos:', msg.stream_position);
    }
  }

  // Format events
  const events = messages.results.map(msg => ({
    sender: msg.sender_user_id,
    type: msg.event_type,
    content: JSON.parse(msg.content),
  }));

  // Get the current max stream position for to-device messages
  // This ensures we always return a valid next_batch, even on first sync
  const currentPos = await db.prepare(`
    SELECT COALESCE(MAX(stream_position), 0) as max_pos FROM to_device_messages
  `).first<{ max_pos: number }>();
  const maxStreamPos = currentPos?.max_pos || 0;

  // Return the appropriate next_batch:
  // - If we returned messages: use the max position of those messages
  // - Otherwise: use the current max stream position (client is caught up)
  let nextBatch: string;
  if (messages.results.length > 0) {
    const maxReturnedPos = Math.max(...messages.results.map(m => m.stream_position));
    nextBatch = String(maxReturnedPos);
  } else {
    // No messages to return - use current max position so client knows where we are
    nextBatch = String(maxStreamPos);
  }

  return { events, nextBatch };
}

// ============================================
// Cleanup old messages (can be called periodically)
// ============================================

export async function cleanupOldToDeviceMessages(db: D1Database, maxAgeMs: number = 7 * 24 * 60 * 60 * 1000): Promise<number> {
  const cutoff = Date.now() - maxAgeMs;

  const result = await db.prepare(`
    DELETE FROM to_device_messages WHERE created_at < ? AND delivered = 1
  `).bind(cutoff).run();

  return result.meta.changes || 0;
}

export default app;
