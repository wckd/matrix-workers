// TURN server integration for VoIP/WebRTC
// Uses Cloudflare Calls TURN service

import type { Env } from '../types';

// Cloudflare TURN API base URL
const TURN_API_URL = 'https://rtc.live.cloudflare.com/v1/turn/keys';

// Cache TTL for credentials (cache for 80% of credential TTL to ensure freshness)
const CACHE_TTL_RATIO = 0.8;

// Default credential TTL (1 hour - balances security and API call frequency)
const DEFAULT_TTL = 3600;

// Minimum TTL to prevent excessive API calls
const MIN_TTL = 300; // 5 minutes

// Maximum TTL allowed by Cloudflare
const MAX_TTL = 86400; // 24 hours

// Per-user rate limiting for credential generation
const USER_RATE_LIMIT_WINDOW = 60; // 1 minute window
const USER_RATE_LIMIT_MAX = 5; // Max 5 requests per minute per user

// Cloudflare STUN servers to include in response
// These help with NAT traversal even when TURN isn't needed
const CLOUDFLARE_STUN_SERVERS = [
  'stun:stun.cloudflare.com:3478',
];

interface CloudflareTurnResponse {
  iceServers: Array<{
    urls: string[];
    username?: string;
    credential?: string;
  }>;
}

interface CachedCredentials {
  username: string;
  password: string;
  uris: string[];
  ttl: number;
  expiresAt: number;
}

// Matrix TURN server response format
export interface MatrixTurnResponse {
  username: string;
  password: string;
  uris: string[];
  ttl: number;
}

// Error types for TURN operations
export class TurnError extends Error {
  constructor(
    message: string,
    public readonly code: 'NOT_CONFIGURED' | 'API_ERROR' | 'INVALID_RESPONSE' | 'RATE_LIMITED' | 'USER_RATE_LIMITED',
    public readonly statusCode?: number,
    public readonly retryAfterMs?: number
  ) {
    super(message);
    this.name = 'TurnError';
  }
}

/**
 * Get TURN credentials from Cloudflare Calls API
 *
 * @param env - Environment bindings containing TURN_KEY_ID and TURN_API_TOKEN
 * @param ttl - Time-to-live for credentials in seconds (default: 3600)
 * @param userId - Optional user ID for per-user rate limiting
 * @returns Matrix-formatted TURN credentials
 * @throws TurnError if TURN is not configured or API fails
 */
export async function getMatrixTurnCredentials(
  env: Env,
  ttl: number = DEFAULT_TTL,
  userId?: string
): Promise<MatrixTurnResponse> {
  // Validate configuration
  if (!env.TURN_KEY_ID || !env.TURN_API_TOKEN) {
    throw new TurnError(
      'TURN server not configured. Set TURN_KEY_ID and TURN_API_TOKEN.',
      'NOT_CONFIGURED'
    );
  }

  // Check per-user rate limit if userId provided
  if (userId) {
    const rateLimitResult = await checkUserRateLimit(env.CACHE, userId);
    if (!rateLimitResult.allowed) {
      throw new TurnError(
        `Rate limited. Try again in ${rateLimitResult.retryAfterMs}ms.`,
        'USER_RATE_LIMITED',
        429,
        rateLimitResult.retryAfterMs
      );
    }
  }

  // Clamp TTL to valid range
  const validTtl = Math.max(MIN_TTL, Math.min(MAX_TTL, ttl));

  // Check cache first
  const cacheKey = `turn_creds:${env.TURN_KEY_ID}:${validTtl}`;
  const cached = await getCachedCredentials(env.CACHE, cacheKey);

  if (cached) {
    return {
      username: cached.username,
      password: cached.password,
      uris: cached.uris,
      ttl: cached.ttl,
    };
  }

  // Fetch fresh credentials from Cloudflare
  const credentials = await fetchTurnCredentials(env, validTtl);

  // Cache the credentials
  await cacheCredentials(env.CACHE, cacheKey, credentials, validTtl);

  return credentials;
}

/**
 * Get STUN-only servers (no credentials needed)
 * Useful as fallback when TURN isn't configured
 */
export function getStunServers(): MatrixTurnResponse {
  return {
    username: '',
    password: '',
    uris: CLOUDFLARE_STUN_SERVERS,
    ttl: 86400, // STUN doesn't need short TTL
  };
}

/**
 * Fetch fresh TURN credentials from Cloudflare Calls API
 */
async function fetchTurnCredentials(
  env: Env,
  ttl: number
): Promise<MatrixTurnResponse> {
  const url = `${TURN_API_URL}/${env.TURN_KEY_ID}/credentials/generate-ice-servers`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.TURN_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ttl }),
    });
  } catch (error) {
    throw new TurnError(
      `Failed to connect to TURN API: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'API_ERROR'
    );
  }

  // Handle rate limiting
  if (response.status === 429) {
    const retryAfter = response.headers.get('Retry-After');
    throw new TurnError(
      `TURN API rate limited. Retry after ${retryAfter || 'unknown'} seconds.`,
      'RATE_LIMITED',
      429
    );
  }

  // Handle other errors
  if (!response.ok) {
    let errorMessage = `TURN API returned ${response.status}`;
    try {
      const errorBody = await response.text();
      if (errorBody) {
        errorMessage += `: ${errorBody}`;
      }
    } catch {
      // Ignore error reading body
    }
    throw new TurnError(errorMessage, 'API_ERROR', response.status);
  }

  // Parse response
  let data: CloudflareTurnResponse;
  try {
    data = await response.json() as CloudflareTurnResponse;
  } catch {
    throw new TurnError('Invalid JSON response from TURN API', 'INVALID_RESPONSE');
  }

  // Validate response structure - Cloudflare returns an array of iceServers
  if (!data.iceServers || !Array.isArray(data.iceServers) || data.iceServers.length === 0) {
    throw new TurnError(
      `TURN API response missing iceServers array. Got: ${JSON.stringify(data)}`,
      'INVALID_RESPONSE'
    );
  }

  // Find the TURN server entry (the one with credentials)
  const turnServer = data.iceServers.find(s => s.username && s.credential);
  if (!turnServer) {
    throw new TurnError(
      `TURN API response has no server with credentials. Got: ${JSON.stringify(data)}`,
      'INVALID_RESPONSE'
    );
  }

  // Collect all URLs from Cloudflare (includes both STUN and TURN)
  const cloudflareUrls = data.iceServers.flatMap(s => s.urls || []);

  // Transform to Matrix format
  return {
    username: turnServer.username!,
    password: turnServer.credential!,
    uris: cloudflareUrls,
    ttl: ttl,
  };
}

/**
 * Get cached credentials if still valid
 */
async function getCachedCredentials(
  cache: KVNamespace,
  key: string
): Promise<CachedCredentials | null> {
  try {
    const cached = await cache.get(key, 'json') as CachedCredentials | null;

    if (!cached) {
      return null;
    }

    // Check if credentials are still valid (with buffer)
    const now = Date.now();
    if (cached.expiresAt <= now) {
      // Expired, delete from cache
      await cache.delete(key);
      return null;
    }

    // Recalculate remaining TTL
    const remainingTtl = Math.floor((cached.expiresAt - now) / 1000);
    return {
      ...cached,
      ttl: remainingTtl,
    };
  } catch {
    // Cache read failed, treat as miss
    return null;
  }
}

/**
 * Cache credentials with appropriate TTL
 */
async function cacheCredentials(
  cache: KVNamespace,
  key: string,
  credentials: MatrixTurnResponse,
  ttl: number
): Promise<void> {
  try {
    const expiresAt = Date.now() + (ttl * 1000 * CACHE_TTL_RATIO);
    const cacheTtl = Math.floor(ttl * CACHE_TTL_RATIO);

    const cached: CachedCredentials = {
      username: credentials.username,
      password: credentials.password,
      uris: credentials.uris,
      ttl: credentials.ttl,
      expiresAt,
    };

    await cache.put(key, JSON.stringify(cached), {
      expirationTtl: cacheTtl,
    });
  } catch {
    // Cache write failed, non-fatal
    console.warn('Failed to cache TURN credentials');
  }
}

/**
 * Check if TURN is configured
 */
export function isTurnConfigured(env: Env): boolean {
  return Boolean(env.TURN_KEY_ID && env.TURN_API_TOKEN);
}

/**
 * Get TURN configuration status for admin/debug
 */
export function getTurnStatus(env: Env): {
  configured: boolean;
  keyId?: string;
} {
  return {
    configured: isTurnConfigured(env),
    keyId: env.TURN_KEY_ID ? `${env.TURN_KEY_ID.slice(0, 8)}...` : undefined,
  };
}

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs?: number;
}

/**
 * Check and update per-user rate limit for TURN credential requests
 */
async function checkUserRateLimit(
  cache: KVNamespace,
  userId: string
): Promise<RateLimitResult> {
  const key = `turn_ratelimit:${userId}`;
  const now = Date.now();
  const windowStart = now - (USER_RATE_LIMIT_WINDOW * 1000);

  try {
    // Get current rate limit data
    const data = await cache.get(key, 'json') as { requests: number[] } | null;

    // Filter to only requests within the window
    const recentRequests = data?.requests?.filter(t => t > windowStart) || [];

    if (recentRequests.length >= USER_RATE_LIMIT_MAX) {
      // Rate limited - calculate when the oldest request will expire
      const oldestRequest = Math.min(...recentRequests);
      const retryAfterMs = (oldestRequest + USER_RATE_LIMIT_WINDOW * 1000) - now;

      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: Math.max(1000, retryAfterMs), // At least 1 second
      };
    }

    // Add this request and save
    recentRequests.push(now);
    await cache.put(key, JSON.stringify({ requests: recentRequests }), {
      expirationTtl: USER_RATE_LIMIT_WINDOW + 10, // Slight buffer
    });

    return {
      allowed: true,
      remaining: USER_RATE_LIMIT_MAX - recentRequests.length,
    };
  } catch {
    // On cache error, allow the request (fail open)
    return { allowed: true, remaining: USER_RATE_LIMIT_MAX };
  }
}
