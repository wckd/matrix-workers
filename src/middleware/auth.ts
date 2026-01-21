// Authentication middleware

import { createMiddleware } from 'hono/factory';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { hashToken } from '../utils/crypto';
import { getUserByTokenHash } from '../services/database';

export type AuthContext = {
  userId: string;
  deviceId: string | null;
  accessToken: string;
};

// Extract access token from request
export function extractAccessToken(request: Request): string | null {
  // Check Authorization header first
  const authHeader = request.headers.get('Authorization');
  if (authHeader) {
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (match) {
      return match[1];
    }
  }

  // Fall back to query parameter
  const url = new URL(request.url);
  const queryToken = url.searchParams.get('access_token');
  if (queryToken) {
    return queryToken;
  }

  return null;
}

// Validate access token and return user info
export async function validateAccessToken(
  db: D1Database,
  token: string
): Promise<AuthContext | null> {
  const tokenHash = await hashToken(token);
  const result = await getUserByTokenHash(db, tokenHash);

  if (!result) {
    return null;
  }

  return {
    userId: result.userId,
    deviceId: result.deviceId,
    accessToken: token,
  };
}

// Middleware that requires authentication
export function requireAuth() {
  return createMiddleware<AppEnv>(async (c, next) => {
    const token = extractAccessToken(c.req.raw);
    const path = new URL(c.req.url).pathname;

    if (!token) {
      // Log full headers for debugging missing token
      const authHeader = c.req.raw.headers.get('Authorization');
      console.log(`[AUTH] Missing token for ${path}. Authorization header: ${authHeader || 'NONE'}`);
      return Errors.missingToken().toResponse();
    }

    // Log token prefix for debugging (first 8 chars only for security)
    const tokenPrefix = token.substring(0, 8);
    console.log(`[AUTH] Validating token ${tokenPrefix}... for ${path}`);

    const auth = await validateAccessToken(c.env.DB, token);

    if (!auth) {
      console.log(`[AUTH] Token ${tokenPrefix}... is INVALID for ${path}. Token length: ${token.length}`);
      return Errors.unknownToken().toResponse();
    }

    console.log(`[AUTH] Token ${tokenPrefix}... valid for user ${auth.userId}`);


    // Store auth context
    c.set('auth', auth);
    c.set('userId', auth.userId);
    c.set('deviceId', auth.deviceId);
    c.set('accessToken', auth.accessToken);

    return next();
  });
}

// Middleware that allows optional authentication
export function optionalAuth() {
  return createMiddleware<AppEnv>(async (c, next) => {
    const token = extractAccessToken(c.req.raw);

    if (token) {
      const auth = await validateAccessToken(c.env.DB, token);
      if (auth) {
        c.set('auth', auth);
        c.set('userId', auth.userId);
        c.set('deviceId', auth.deviceId);
        c.set('accessToken', auth.accessToken);
      }
    }

    return next();
  });
}
