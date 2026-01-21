// Typing Indicators API
// Implements: https://spec.matrix.org/v1.12/client-server-api/#typing-notifications
//
// Typing notifications inform other users when someone is typing.
// They are ephemeral - stored in Room Durable Objects (not D1).

import { Hono } from 'hono';
import type { AppEnv, Env } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';

const app = new Hono<AppEnv>();

// ============================================
// Constants
// ============================================

const DEFAULT_TYPING_TIMEOUT = 30000; // 30 seconds
const MAX_TYPING_TIMEOUT = 120000; // 2 minutes

// ============================================
// Helper to get Room DO stub
// ============================================

function getRoomDO(env: Env, roomId: string) {
  const id = env.ROOMS.idFromName(roomId);
  return env.ROOMS.get(id);
}

// ============================================
// Endpoints
// ============================================

// PUT /_matrix/client/v3/rooms/:roomId/typing/:userId - Set typing status
app.put('/_matrix/client/v3/rooms/:roomId/typing/:userId', requireAuth(), async (c) => {
  const requestingUserId = c.get('userId');
  const roomId = c.req.param('roomId');
  const targetUserId = c.req.param('userId');
  const db = c.env.DB;

  console.log('[typing] PUT request from', requestingUserId, 'for user', targetUserId, 'in room', roomId);

  // Users can only set their own typing status
  if (requestingUserId !== targetUserId) {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Cannot set typing status for other users',
    }, 403);
  }

  // Check membership
  const membership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, requestingUserId).first<{ membership: string }>();

  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  let body: { typing: boolean; timeout?: number };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { typing, timeout: requestedTimeout } = body;

  if (typeof typing !== 'boolean') {
    return Errors.missingParam('typing').toResponse();
  }

  // Calculate timeout
  let timeout = DEFAULT_TYPING_TIMEOUT;
  if (typing && requestedTimeout) {
    timeout = Math.min(requestedTimeout, MAX_TYPING_TIMEOUT);
  }

  // Set typing status in Room Durable Object
  const roomDO = getRoomDO(c.env, roomId);
  await roomDO.fetch(new Request('https://room/typing', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id: requestingUserId,
      typing,
      timeout,
    }),
  }));

  console.log('[typing] User', requestingUserId, typing ? 'started' : 'stopped', 'typing in room', roomId);

  return c.json({});
});

// ============================================
// Internal Helpers
// ============================================

// Get typing users for a room (for sync) - uses Room Durable Object
export async function getTypingUsers(
  env: Env,
  roomId: string
): Promise<string[]> {
  const roomDO = getRoomDO(env, roomId);
  const response = await roomDO.fetch(new Request('https://room/typing', {
    method: 'GET',
  }));

  const data = await response.json() as { user_ids: string[] };
  return data.user_ids;
}

// Get typing status for multiple rooms (for sync) - uses Room Durable Objects
export async function getTypingForRooms(
  env: Env,
  roomIds: string[]
): Promise<Record<string, string[]>> {
  if (roomIds.length === 0) return {};

  const byRoom: Record<string, string[]> = {};

  // Fetch typing state from each Room DO in parallel
  const results = await Promise.all(
    roomIds.map(async (roomId) => {
      try {
        const users = await getTypingUsers(env, roomId);
        return { roomId, users };
      } catch {
        return { roomId, users: [] };
      }
    })
  );

  for (const { roomId, users } of results) {
    if (users.length > 0) {
      byRoom[roomId] = users;
    }
  }

  return byRoom;
}

export default app;
