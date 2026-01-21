// Room Aliases API
// Implements: https://spec.matrix.org/v1.12/client-server-api/#room-aliases
//
// Room aliases provide human-readable names for rooms (e.g., #general:server.org)

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';

const app = new Hono<AppEnv>();

// ============================================
// Endpoints
// ============================================

// GET /_matrix/client/v3/directory/room/:roomAlias - Resolve room alias
app.get('/_matrix/client/v3/directory/room/:roomAlias', async (c) => {
  const roomAlias = decodeURIComponent(c.req.param('roomAlias'));
  const db = c.env.DB;

  // Find alias in database
  const alias = await db.prepare(`
    SELECT room_id, servers FROM room_aliases WHERE alias = ?
  `).bind(roomAlias).first<{ room_id: string; servers: string | null }>();

  if (!alias) {
    return Errors.notFound('Room alias not found').toResponse();
  }

  // Parse servers list
  let servers: string[] = [c.env.SERVER_NAME];
  if (alias.servers) {
    try {
      servers = JSON.parse(alias.servers);
    } catch {
      // Use default
    }
  }

  return c.json({
    room_id: alias.room_id,
    servers,
  });
});

// PUT /_matrix/client/v3/directory/room/:roomAlias - Create room alias
app.put('/_matrix/client/v3/directory/room/:roomAlias', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomAlias = decodeURIComponent(c.req.param('roomAlias'));
  const db = c.env.DB;

  let body: { room_id: string };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  if (!body.room_id) {
    return Errors.missingParam('room_id').toResponse();
  }

  // Validate alias format
  if (!roomAlias.startsWith('#') || !roomAlias.includes(':')) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'Invalid room alias format',
    }, 400);
  }

  // Check alias is for our server
  const [, aliasServer] = roomAlias.split(':');
  if (aliasServer !== c.env.SERVER_NAME) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'Cannot create alias for another server',
    }, 400);
  }

  // Check room exists
  const room = await db.prepare(`
    SELECT room_id FROM rooms WHERE room_id = ?
  `).bind(body.room_id).first();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Check user is member of room
  const membership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(body.room_id, userId).first<{ membership: string }>();

  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Check alias doesn't already exist
  const existing = await db.prepare(`
    SELECT alias FROM room_aliases WHERE alias = ?
  `).bind(roomAlias).first();

  if (existing) {
    return c.json({
      errcode: 'M_ROOM_IN_USE',
      error: 'Room alias already exists',
    }, 409);
  }

  // Create alias
  await db.prepare(`
    INSERT INTO room_aliases (alias, room_id, creator_id, servers, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(roomAlias, body.room_id, userId, JSON.stringify([c.env.SERVER_NAME]), Date.now()).run();

  return c.json({});
});

// DELETE /_matrix/client/v3/directory/room/:roomAlias - Delete room alias
app.delete('/_matrix/client/v3/directory/room/:roomAlias', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomAlias = decodeURIComponent(c.req.param('roomAlias'));
  const db = c.env.DB;

  // Find alias
  const alias = await db.prepare(`
    SELECT room_id, creator_id FROM room_aliases WHERE alias = ?
  `).bind(roomAlias).first<{ room_id: string; creator_id: string }>();

  if (!alias) {
    return Errors.notFound('Room alias not found').toResponse();
  }

  // Check permissions - creator or room admin can delete
  const canDelete = alias.creator_id === userId;

  if (!canDelete) {
    // Check if user has power to delete aliases in the room
    const powerLevels = await db.prepare(`
      SELECT e.content FROM room_state rs
      JOIN events e ON rs.event_id = e.event_id
      WHERE rs.room_id = ? AND rs.event_type = 'm.room.power_levels'
    `).bind(alias.room_id).first<{ content: string }>();

    if (powerLevels) {
      try {
        const levels = JSON.parse(powerLevels.content);
        const userPower = levels.users?.[userId] || levels.users_default || 0;
        const aliasLevel = levels.state_default || 50;

        if (userPower < aliasLevel) {
          return Errors.forbidden('Insufficient power level to delete alias').toResponse();
        }
      } catch {
        return Errors.forbidden('Cannot delete alias').toResponse();
      }
    } else {
      return Errors.forbidden('Cannot delete alias').toResponse();
    }
  }

  // Delete alias
  await db.prepare(`
    DELETE FROM room_aliases WHERE alias = ?
  `).bind(roomAlias).run();

  return c.json({});
});

// GET /_matrix/client/v3/directory/list/room/:roomId - Get room visibility
app.get('/_matrix/client/v3/directory/list/room/:roomId', async (c) => {
  const roomId = c.req.param('roomId');
  const db = c.env.DB;

  const room = await db.prepare(`
    SELECT is_public FROM rooms WHERE room_id = ?
  `).bind(roomId).first<{ is_public: number }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  return c.json({
    visibility: room.is_public ? 'public' : 'private',
  });
});

// PUT /_matrix/client/v3/directory/list/room/:roomId - Set room visibility
app.put('/_matrix/client/v3/directory/list/room/:roomId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const db = c.env.DB;

  let body: { visibility: 'public' | 'private' };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  if (!body.visibility || !['public', 'private'].includes(body.visibility)) {
    return Errors.missingParam('visibility').toResponse();
  }

  // Check user has power to change visibility
  const membership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, userId).first<{ membership: string }>();

  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Check power level
  const powerLevels = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.power_levels'
  `).bind(roomId).first<{ content: string }>();

  if (powerLevels) {
    try {
      const levels = JSON.parse(powerLevels.content);
      const userPower = levels.users?.[userId] || levels.users_default || 0;
      const requiredPower = levels.state_default || 50;

      if (userPower < requiredPower) {
        return Errors.forbidden('Insufficient power level').toResponse();
      }
    } catch {
      return Errors.forbidden('Cannot change visibility').toResponse();
    }
  }

  // Update visibility
  await db.prepare(`
    UPDATE rooms SET is_public = ? WHERE room_id = ?
  `).bind(body.visibility === 'public' ? 1 : 0, roomId).run();

  return c.json({});
});

export default app;
