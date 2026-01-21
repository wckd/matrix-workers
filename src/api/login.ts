// Matrix login/registration endpoints

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { hashPassword, verifyPassword, hashToken } from '../utils/crypto';
import {
  formatUserId,
  generateDeviceId,
  generateAccessToken,
  generateOpaqueId,
  isValidLocalpart,
} from '../utils/ids';
import {
  createUser,
  getUserByLocalpart,
  getUserById,
  getPasswordHash,
  createDevice,
  createAccessToken,
  deleteAccessToken,
  deleteAllUserTokens,
} from '../services/database';
import { requireAuth, extractAccessToken } from '../middleware/auth';

const app = new Hono<AppEnv>();

// GET /_matrix/client/v3/login - Get supported login flows
app.get('/_matrix/client/v3/login', (c) => {
  return c.json({
    flows: [
      {
        type: 'm.login.password',
      },
      {
        type: 'm.login.token',
      },
    ],
  });
});

// POST /_matrix/client/v3/login - Login
app.post('/_matrix/client/v3/login', async (c) => {
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { type, identifier, password, token, device_id, initial_device_display_name } = body;

  let userId: string;

  if (type === 'm.login.token') {
    // Token-based login (for QR codes)
    if (!token) {
      return Errors.missingParam('token').toResponse();
    }

    // Look up the token in KV
    const tokenHash = await hashToken(token);
    const tokenData = await c.env.SESSIONS.get(`login_token:${tokenHash}`, 'json') as {
      user_id: string;
      expires_at: number;
    } | null;

    if (!tokenData) {
      return Errors.forbidden('Invalid or expired login token').toResponse();
    }

    // Check expiration
    if (Date.now() > tokenData.expires_at) {
      // Clean up expired token
      await c.env.SESSIONS.delete(`login_token:${tokenHash}`);
      return Errors.forbidden('Login token has expired').toResponse();
    }

    userId = tokenData.user_id;

    // Delete the token (one-time use)
    await c.env.SESSIONS.delete(`login_token:${tokenHash}`);

  } else if (type === 'm.login.password') {
    // Password-based login
    if (!identifier || !password) {
      return Errors.missingParam('identifier or password').toResponse();
    }

    // Parse identifier
    if (identifier.type === 'm.id.user') {
      // Can be full user ID or just localpart
      if (identifier.user.startsWith('@')) {
        userId = identifier.user;
      } else {
        userId = formatUserId(identifier.user, c.env.SERVER_NAME);
      }
    } else {
      return Errors.unrecognized('Unknown identifier type').toResponse();
    }

    // Get stored password hash
    const storedHash = await getPasswordHash(c.env.DB, userId);
    if (!storedHash) {
      return Errors.forbidden('Invalid username or password').toResponse();
    }

    // Verify password
    const valid = await verifyPassword(password, storedHash);
    if (!valid) {
      return Errors.forbidden('Invalid username or password').toResponse();
    }
  } else {
    return Errors.unrecognized('Unknown login type').toResponse();
  }

  // Check if user is deactivated
  const user = await getUserById(c.env.DB, userId);
  if (!user) {
    return Errors.forbidden('Invalid username or password').toResponse();
  }
  if (user.is_deactivated) {
    return Errors.userDeactivated().toResponse();
  }

  // Generate or use provided device ID
  const deviceId = device_id || await generateDeviceId();

  // Create device
  await createDevice(c.env.DB, userId, deviceId, initial_device_display_name);

  // Generate access token
  const accessToken = await generateAccessToken();
  const tokenHash = await hashToken(accessToken);
  const tokenId = await generateOpaqueId(16);

  await createAccessToken(c.env.DB, tokenId, tokenHash, userId, deviceId);

  return c.json({
    user_id: userId,
    access_token: accessToken,
    device_id: deviceId,
    home_server: c.env.SERVER_NAME,
  });
});

// POST /_matrix/client/v3/logout - Logout current session
app.post('/_matrix/client/v3/logout', requireAuth(), async (c) => {
  const token = extractAccessToken(c.req.raw);
  if (token) {
    const tokenHash = await hashToken(token);
    await deleteAccessToken(c.env.DB, tokenHash);
  }
  return c.json({});
});

// POST /_matrix/client/v3/logout/all - Logout all sessions
app.post('/_matrix/client/v3/logout/all', requireAuth(), async (c) => {
  const userId = c.get('userId');
  await deleteAllUserTokens(c.env.DB, userId);
  return c.json({});
});

// GET /_matrix/client/v3/register/available - Check if username is available
app.get('/_matrix/client/v3/register/available', async (c) => {
  const username = c.req.query('username');

  if (!username) {
    return Errors.missingParam('username').toResponse();
  }

  if (!isValidLocalpart(username)) {
    return Errors.invalidUsername('Username contains invalid characters').toResponse();
  }

  const existing = await getUserByLocalpart(c.env.DB, username);
  if (existing) {
    return Errors.userInUse().toResponse();
  }

  return c.json({ available: true });
});

// POST /_matrix/client/v3/register - Register new user
app.post('/_matrix/client/v3/register', async (c) => {
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const {
    username,
    password,
    device_id,
    initial_device_display_name,
    inhibit_login,
    auth,
  } = body;

  // Check registration kind
  const kind = c.req.query('kind') || 'user';
  if (kind !== 'user' && kind !== 'guest') {
    return Errors.invalidParam('kind', 'Invalid registration kind').toResponse();
  }

  const isGuest = kind === 'guest';

  // For non-guests, require username and password
  if (!isGuest) {
    // Simple auth - in production, implement UIA (User-Interactive Authentication)
    if (!auth || auth.type !== 'm.login.dummy') {
      // Return UIA requirements
      const sessionId = await generateOpaqueId(16);
      return c.json({
        flows: [{ stages: ['m.login.dummy'] }],
        params: {},
        session: sessionId,
      }, 401);
    }

    if (!username) {
      return Errors.missingParam('username').toResponse();
    }

    if (!isValidLocalpart(username)) {
      return Errors.invalidUsername('Username contains invalid characters').toResponse();
    }

    if (!password) {
      return Errors.missingParam('password').toResponse();
    }
  }

  // Generate localpart for guests
  const localpart = isGuest ? await generateOpaqueId(12) : username;
  const userId = formatUserId(localpart, c.env.SERVER_NAME);

  // Check if user already exists
  const existing = await getUserById(c.env.DB, userId);
  if (existing) {
    return Errors.userInUse().toResponse();
  }

  // Hash password (null for guests)
  const passwordHash = password ? await hashPassword(password) : null;

  // Create user
  await createUser(c.env.DB, userId, localpart, passwordHash, isGuest);

  // Response depends on inhibit_login
  if (inhibit_login) {
    return c.json({
      user_id: userId,
      home_server: c.env.SERVER_NAME,
    });
  }

  // Generate device and access token
  const deviceId = device_id || await generateDeviceId();
  await createDevice(c.env.DB, userId, deviceId, initial_device_display_name);

  const accessToken = await generateAccessToken();
  const tokenHash = await hashToken(accessToken);
  const tokenId = await generateOpaqueId(16);

  await createAccessToken(c.env.DB, tokenId, tokenHash, userId, deviceId);

  return c.json({
    user_id: userId,
    access_token: accessToken,
    device_id: deviceId,
    home_server: c.env.SERVER_NAME,
  });
});

// GET /_matrix/client/v3/account/whoami - Get current user info
app.get('/_matrix/client/v3/account/whoami', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const deviceId = c.get('deviceId');

  const user = await getUserById(c.env.DB, userId);
  if (!user) {
    return Errors.unknownToken().toResponse();
  }

  return c.json({
    user_id: userId,
    device_id: deviceId,
    is_guest: user.is_guest,
  });
});

export default app;
