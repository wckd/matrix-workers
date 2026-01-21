// Server Notices API
// Implements server-generated notices to users
//
// Server notices are messages sent by the server to inform users about
// important events like terms of service updates, security alerts, etc.

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';
import { generateOpaqueId, generateEventId } from '../utils/ids';

const app = new Hono<AppEnv>();

// Server notice room configuration
const SERVER_NOTICE_ROOM_TYPE = 'm.server_notice';
const SERVER_NOTICE_USER_LOCALPART = 'server';

// ============================================
// Internal Functions
// ============================================

// Get or create the server notice user
async function getServerNoticeUser(db: D1Database, serverName: string): Promise<string> {
  const userId = `@${SERVER_NOTICE_USER_LOCALPART}:${serverName}`;

  const existing = await db.prepare(`
    SELECT user_id FROM users WHERE user_id = ?
  `).bind(userId).first();

  if (!existing) {
    // Create the server notice user
    await db.prepare(`
      INSERT INTO users (user_id, localpart, display_name, admin, is_guest, is_deactivated)
      VALUES (?, ?, 'Server Notices', 0, 0, 0)
    `).bind(userId, SERVER_NOTICE_USER_LOCALPART).run();
  }

  return userId;
}

// Get or create a server notice room for a user
async function getOrCreateNoticeRoom(
  db: D1Database,
  serverName: string,
  targetUserId: string
): Promise<string> {
  // Check if user already has a server notice room
  const existing = await db.prepare(`
    SELECT rm.room_id FROM room_memberships rm
    JOIN room_state rs ON rm.room_id = rs.room_id
    JOIN events e ON rs.event_id = e.event_id
    WHERE rm.user_id = ?
      AND rs.event_type = 'm.room.create'
      AND e.content LIKE '%"type":"m.server_notice"%'
    LIMIT 1
  `).bind(targetUserId).first<{ room_id: string }>();

  if (existing) {
    return existing.room_id;
  }

  // Create a new server notice room
  const serverUserId = await getServerNoticeUser(db, serverName);
  const roomId = `!${await generateOpaqueId(18)}:${serverName}`;
  const now = Date.now();

  // Create room
  await db.prepare(`
    INSERT INTO rooms (room_id, room_version, is_public, creator_id, created_at)
    VALUES (?, '10', 0, ?, ?)
  `).bind(roomId, serverUserId, now).run();

  // Create room events
  const events = [
    {
      type: 'm.room.create',
      state_key: '',
      content: {
        creator: serverUserId,
        room_version: '10',
        type: SERVER_NOTICE_ROOM_TYPE,
      },
    },
    {
      type: 'm.room.name',
      state_key: '',
      content: {
        name: 'Server Notices',
      },
    },
    {
      type: 'm.room.join_rules',
      state_key: '',
      content: {
        join_rule: 'invite',
      },
    },
    {
      type: 'm.room.history_visibility',
      state_key: '',
      content: {
        history_visibility: 'joined',
      },
    },
    {
      type: 'm.room.power_levels',
      state_key: '',
      content: {
        users: {
          [serverUserId]: 100,
        },
        users_default: 0,
        events_default: 50,
        state_default: 50,
        ban: 50,
        kick: 50,
        redact: 50,
        invite: 0,
      },
    },
    {
      type: 'm.room.member',
      state_key: serverUserId,
      content: {
        membership: 'join',
        displayname: 'Server Notices',
      },
    },
    {
      type: 'm.room.member',
      state_key: targetUserId,
      content: {
        membership: 'invite',
      },
    },
  ];

  let depth = 1;
  let prevEvents: string[] = [];
  const authEvents: string[] = [];

  for (const event of events) {
    const eventId = await generateEventId(serverName);

    await db.prepare(`
      INSERT INTO events (
        event_id, room_id, sender, event_type, state_key, content,
        origin_server_ts, depth, auth_events, prev_events
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      eventId,
      roomId,
      serverUserId,
      event.type,
      event.state_key,
      JSON.stringify(event.content),
      now + depth,
      depth,
      JSON.stringify(authEvents),
      JSON.stringify(prevEvents)
    ).run();

    // Update room state
    await db.prepare(`
      INSERT OR REPLACE INTO room_state (room_id, event_type, state_key, event_id)
      VALUES (?, ?, ?, ?)
    `).bind(roomId, event.type, event.state_key, eventId).run();

    // Track auth events
    if (['m.room.create', 'm.room.power_levels', 'm.room.join_rules'].includes(event.type)) {
      authEvents.push(eventId);
    }

    prevEvents = [eventId];
    depth++;
  }

  // Create memberships
  await db.prepare(`
    INSERT INTO room_memberships (room_id, user_id, membership, event_id, display_name)
    VALUES (?, ?, 'join', ?, 'Server Notices')
  `).bind(roomId, serverUserId, prevEvents[0]).run();

  await db.prepare(`
    INSERT INTO room_memberships (room_id, user_id, membership, event_id)
    VALUES (?, ?, 'invite', ?)
  `).bind(roomId, targetUserId, prevEvents[0]).run();

  return roomId;
}

// Send a server notice to a user
export async function sendServerNotice(
  db: D1Database,
  serverName: string,
  targetUserId: string,
  body: string,
  msgtype: string = 'm.text',
  adminContact?: string
): Promise<string> {
  const roomId = await getOrCreateNoticeRoom(db, serverName, targetUserId);
  const serverUserId = await getServerNoticeUser(db, serverName);
  const eventId = await generateEventId(serverName);
  const now = Date.now();

  // Get latest event for prev_events
  const latest = await db.prepare(`
    SELECT event_id, depth FROM events WHERE room_id = ? ORDER BY depth DESC LIMIT 1
  `).bind(roomId).first<{ event_id: string; depth: number }>();

  const depth = (latest?.depth || 0) + 1;
  const prevEvents = latest ? [latest.event_id] : [];

  // Get auth events
  const authEventRows = await db.prepare(`
    SELECT e.event_id FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type IN ('m.room.create', 'm.room.power_levels', 'm.room.member')
    AND (rs.state_key = '' OR rs.state_key = ?)
  `).bind(roomId, serverUserId).all<{ event_id: string }>();

  const authEvents = authEventRows.results.map(r => r.event_id);

  const content: Record<string, any> = {
    msgtype,
    body,
  };

  if (adminContact) {
    content.admin_contact = adminContact;
  }

  // Server notice specific content
  content['m.server_notice_type'] = 'm.server_notice.usage_limit_reached'; // or other types

  await db.prepare(`
    INSERT INTO events (
      event_id, room_id, sender, event_type, content,
      origin_server_ts, depth, auth_events, prev_events
    ) VALUES (?, ?, ?, 'm.room.message', ?, ?, ?, ?, ?)
  `).bind(
    eventId,
    roomId,
    serverUserId,
    JSON.stringify(content),
    now,
    depth,
    JSON.stringify(authEvents),
    JSON.stringify(prevEvents)
  ).run();

  return eventId;
}

// ============================================
// Admin Endpoints for Server Notices
// ============================================

// POST /_synapse/admin/v1/send_server_notice - Send a server notice (Synapse-compatible)
app.post('/_synapse/admin/v1/send_server_notice', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  // Check if user is admin
  const user = await db.prepare(`
    SELECT admin FROM users WHERE user_id = ?
  `).bind(userId).first<{ admin: number }>();

  if (!user || user.admin !== 1) {
    return Errors.forbidden('Admin access required').toResponse();
  }

  let body: {
    user_id: string;
    content: {
      msgtype: string;
      body: string;
      admin_contact?: string;
    };
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  if (!body.user_id || !body.content?.body) {
    return Errors.missingParam('user_id or content.body').toResponse();
  }

  const eventId = await sendServerNotice(
    db,
    c.env.SERVER_NAME,
    body.user_id,
    body.content.body,
    body.content.msgtype || 'm.text',
    body.content.admin_contact
  );

  return c.json({ event_id: eventId });
});

// POST /_matrix/client/v3/admin/send_server_notice - Alternative endpoint
app.post('/_matrix/client/v3/admin/send_server_notice', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  // Check if user is admin
  const user = await db.prepare(`
    SELECT admin FROM users WHERE user_id = ?
  `).bind(userId).first<{ admin: number }>();

  if (!user || user.admin !== 1) {
    return Errors.forbidden('Admin access required').toResponse();
  }

  let body: {
    user_id: string;
    content: {
      msgtype: string;
      body: string;
    };
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  if (!body.user_id || !body.content?.body) {
    return Errors.missingParam('user_id or content.body').toResponse();
  }

  const eventId = await sendServerNotice(
    db,
    c.env.SERVER_NAME,
    body.user_id,
    body.content.body,
    body.content.msgtype || 'm.text'
  );

  return c.json({ event_id: eventId });
});

export default app;
