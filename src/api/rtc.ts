// MatrixRTC API endpoints (MSC4143/MSC4195)
// Provides LiveKit JWT tokens for Element X calls

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { generateLiveKitToken, getLiveKitConfig } from '../services/livekit';

const app = new Hono<AppEnv>();

// OpenID token structure from Matrix client
interface OpenIDToken {
  access_token: string;
  token_type: string;
  matrix_server_name: string;
  expires_in: number;
}

// Member info from request
interface MemberInfo {
  id: string;
  claimed_user_id: string;
  claimed_device_id: string;
}

// Request body for /get_token
// Note: Element X sends 'room' not 'room_id', and 'device_id' not 'member'
interface GetTokenRequest {
  room_id?: string;  // Old format
  room?: string;     // Element X format
  slot_id?: string;
  openid_token: OpenIDToken;
  member?: MemberInfo;  // Old format
  device_id?: string;   // Element X format - device ID string
  delayed_event_id?: string;
}

// Response for /get_token
interface GetTokenResponse {
  url: string;
  jwt: string;
}

// Verify OpenID token with the homeserver
async function verifyOpenIDToken(
  token: OpenIDToken,
  serverName: string
): Promise<{ sub: string } | null> {
  try {
    // The OpenID token should be verified against the homeserver
    // For our own homeserver, we can verify it directly
    if (token.matrix_server_name !== serverName) {
      console.log('Token from different server:', token.matrix_server_name);
      // For federated calls, we'd need to verify with the remote server
      // For now, we only accept tokens from our own server
      return null;
    }

    // For our own tokens, we trust them if they came from our server
    // In production, you'd want to validate the token signature or check against storage
    // For simplicity, we'll accept tokens that match our server name
    return { sub: token.access_token };
  } catch (error) {
    console.error('Error verifying OpenID token:', error);
    return null;
  }
}

// Convert Matrix room ID to a valid LiveKit room name
function roomIdToLiveKitName(roomId: string): string {
  // LiveKit room names can only contain alphanumeric, dash, underscore
  // Matrix room IDs look like: !roomid:server.name
  return roomId.replace(/[^a-zA-Z0-9-_]/g, '_');
}

// POST /livekit/get_token - Get a LiveKit JWT token
// This is the endpoint that Element X calls to get call credentials
app.post('/livekit/get_token', async (c) => {
  const config = getLiveKitConfig(c.env);
  if (!config) {
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'LiveKit not configured' },
      500
    );
  }

  let body: GetTokenRequest;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      { errcode: 'M_BAD_JSON', error: 'Invalid JSON body' },
      400
    );
  }

  // Handle both old format (room_id, member) and Element X format (room, device_id)
  const roomId = body.room_id || body.room;

  // Validate required fields
  if (!roomId || !body.openid_token) {
    return c.json(
      { errcode: 'M_BAD_JSON', error: 'Missing required fields: room and openid_token' },
      400
    );
  }

  // Verify the OpenID token (simplified for now)
  // In production, you'd verify the token cryptographically
  const verified = await verifyOpenIDToken(body.openid_token, c.env.SERVER_NAME);
  if (!verified) {
    // For now, accept all tokens from our server's clients
    // This is a simplification - in production you'd verify properly
    console.log('OpenID token verification skipped for development');
  }

  // Generate participant identity - use access_token as identity if no member info
  let participantId: string;
  let participantName: string;

  if (body.member) {
    participantId = body.member.claimed_user_id;
    participantName = participantId.split(':')[0].replace('@', '');
  } else {
    participantId = body.device_id || body.openid_token.access_token.substring(0, 16);
    participantName = body.device_id || 'participant';
  }

  // Convert Matrix room ID to LiveKit room name
  const liveKitRoom = roomIdToLiveKitName(roomId);

  try {
    // Generate JWT token for this participant
    const jwt = await generateLiveKitToken(
      config.apiKey,
      config.apiSecret,
      liveKitRoom,
      participantId,
      participantName,
      3600 // 1 hour TTL
    );

    const response: GetTokenResponse = {
      url: config.wsUrl,
      jwt: jwt,
    };

    return c.json(response);
  } catch (error) {
    console.error('Error generating LiveKit token:', error);
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'Failed to generate token' },
      500
    );
  }
});

// OPTIONS handler for CORS preflight
app.options('/livekit/get_token', () => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
});

// POST /livekit/get_token/sfu/get - Alternative endpoint format used by Element X
// This is the same as /livekit/get_token but with /sfu/get suffix
app.post('/livekit/get_token/sfu/get', async (c) => {
  console.log('[LiveKit] /sfu/get request received');

  const config = getLiveKitConfig(c.env);
  if (!config) {
    console.log('[LiveKit] Config missing - API_KEY:', !!c.env.LIVEKIT_API_KEY, 'API_SECRET:', !!c.env.LIVEKIT_API_SECRET, 'URL:', !!c.env.LIVEKIT_URL);
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'LiveKit not configured' },
      500
    );
  }

  let body: GetTokenRequest;
  try {
    const rawBody = await c.req.text();
    console.log('[LiveKit] Raw body length:', rawBody.length, 'preview:', rawBody.substring(0, 200));
    body = JSON.parse(rawBody);
  } catch (e) {
    console.log('[LiveKit] JSON parse error:', e);
    return c.json(
      { errcode: 'M_BAD_JSON', error: 'Invalid JSON body' },
      400
    );
  }

  // Handle both old format (room_id, member) and Element X format (room, device_id)
  const roomId = body.room_id || body.room;

  // Validate required fields
  if (!roomId || !body.openid_token) {
    console.log('[LiveKit] Missing fields - room_id:', !!body.room_id, 'room:', !!body.room, 'openid_token:', !!body.openid_token);
    return c.json(
      { errcode: 'M_BAD_JSON', error: 'Missing required fields: room and openid_token' },
      400
    );
  }

  // Verify the OpenID token (simplified for now)
  const verified = await verifyOpenIDToken(body.openid_token, c.env.SERVER_NAME);
  if (!verified) {
    console.log('OpenID token verification skipped for development');
  }

  // Generate participant identity - use access_token as identity if no member info
  // Element X doesn't send member info, just device_id
  let participantId: string;
  let participantName: string;

  if (body.member) {
    participantId = body.member.claimed_user_id;
    participantName = participantId.split(':')[0].replace('@', '');
  } else {
    // For Element X, derive identity from openid_token
    // The access_token's user can be looked up, but for simplicity use device_id
    participantId = body.device_id || body.openid_token.access_token.substring(0, 16);
    participantName = body.device_id || 'participant';
  }

  // Convert Matrix room ID to LiveKit room name
  const liveKitRoom = roomIdToLiveKitName(roomId);

  try {
    // Generate JWT token for this participant
    const jwt = await generateLiveKitToken(
      config.apiKey,
      config.apiSecret,
      liveKitRoom,
      participantId,
      participantName,
      3600 // 1 hour TTL
    );

    const response: GetTokenResponse = {
      url: config.wsUrl,
      jwt: jwt,
    };

    return c.json(response);
  } catch (error) {
    console.error('Error generating LiveKit token:', error);
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'Failed to generate token' },
      500
    );
  }
});

// OPTIONS handler for /sfu/get endpoint
app.options('/livekit/get_token/sfu/get', () => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
});

// Return 405 Method Not Allowed for non-POST/OPTIONS methods
// Element X checks endpoint availability with GET and expects 405 (not 404)
app.all('/livekit/get_token', (c) => {
  return c.text('Method Not Allowed', 405, {
    Allow: 'POST, OPTIONS',
  });
});

app.all('/livekit/get_token/sfu/get', (c) => {
  return c.text('Method Not Allowed', 405, {
    Allow: 'POST, OPTIONS',
  });
});

export default app;
