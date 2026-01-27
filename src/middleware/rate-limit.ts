// Rate Limiting Middleware
// Implements rate limiting using D1 for persistence and KV for fast checks
//
// Uses a sliding window algorithm with different limits for different endpoints

import type { Context, Next } from 'hono';
import type { AppEnv } from '../types';

/* DISABLED - Rate limiting temporarily disabled due to KV rate limit issues
// Rate limit configurations for different endpoint types
const RATE_LIMITS: Record<string, { requests: number; windowMs: number }> = {
  'login': { requests: 10, windowMs: 60 * 1000 },
  'register': { requests: 5, windowMs: 60 * 1000 },
  'default': { requests: 100, windowMs: 60 * 1000 },
  'sync': { requests: 300, windowMs: 60 * 1000 },
  'e2ee': { requests: 500, windowMs: 60 * 1000 },
  'media_upload': { requests: 30, windowMs: 60 * 1000 },
  'media_download': { requests: 200, windowMs: 60 * 1000 },
  'search': { requests: 30, windowMs: 60 * 1000 },
  'federation': { requests: 500, windowMs: 60 * 1000 },
  'send_message': { requests: 60, windowMs: 60 * 1000 },
  'create_room': { requests: 10, windowMs: 60 * 1000 },
};

function getRateLimitType(path: string, method: string): string {
  if (path.includes('/login') && method === 'POST') return 'login';
  if (path.includes('/register') && method === 'POST') return 'register';
  if (path.includes('/sync')) return 'sync';
  if (path.includes('/keys/')) return 'e2ee';
  if (path.includes('/media') || path.includes('/upload')) {
    return method === 'POST' || method === 'PUT' ? 'media_upload' : 'media_download';
  }
  if (path.includes('/search')) return 'search';
  if (path.includes('/_matrix/federation') || path.includes('/_matrix/key')) return 'federation';
  if (path.includes('/createRoom') && method === 'POST') return 'create_room';
  if (path.match(/\/rooms\/[^/]+\/send/) && method === 'PUT') return 'send_message';
  return 'default';
}
END OF DISABLED CODE */

// Get client identifier (IP or user ID)
function getClientId(c: Context<AppEnv>): string {
  // Try to get user ID first (for authenticated requests)
  const userId = c.get('userId');
  if (userId) {
    return `user:${userId}`;
  }

  // Fall back to IP address
  const cfConnectingIp = c.req.header('CF-Connecting-IP');
  const xForwardedFor = c.req.header('X-Forwarded-For');
  const ip = cfConnectingIp || xForwardedFor?.split(',')[0]?.trim() || 'unknown';

  return `ip:${ip}`;
}

// Rate limiter using KV for fast checks
// TEMPORARILY DISABLED: KV itself is hitting rate limits (429) which causes cascading failures
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function rateLimitMiddleware(_c: Context<AppEnv>, next: Next) {
  // DISABLED: Skip all rate limiting to avoid KV 429 errors
  // The KV-based approach doesn't scale with high request volumes
  return next();

  /* DISABLED - KV rate limiting causing issues
  const path = _c.req.path;
  const method = _c.req.method;

  // Skip rate limiting for OPTIONS (CORS preflight)
  if (method === 'OPTIONS') {
    return next();
  }

  // Skip rate limiting for sync endpoints to reduce KV writes
  // Sync endpoints have their own natural rate limiting via timeout parameter
  if (path.includes('/sync')) {
    return next();
  }

  const limitType = getRateLimitType(path, method);
  const config = RATE_LIMITS[limitType];
  const clientId = getClientId(c);

  // Create a unique key for this client + limit type
  const key = `ratelimit:${limitType}:${clientId}`;
  const now = Date.now();
  const windowStart = now - config.windowMs;

  try {
    // Get current count from KV
    const cached = await c.env.CACHE.get(key);

    if (cached) {
      const data = JSON.parse(cached) as { count: number; firstRequest: number };

      // Check if we're still in the same window
      if (data.firstRequest > windowStart) {
        // Still in window, check count
        if (data.count >= config.requests) {
          // Rate limited
          const retryAfter = Math.ceil((data.firstRequest + config.windowMs - now) / 1000);

          c.header('Retry-After', String(retryAfter));
          c.header('X-RateLimit-Limit', String(config.requests));
          c.header('X-RateLimit-Remaining', '0');
          c.header('X-RateLimit-Reset', String(Math.ceil((data.firstRequest + config.windowMs) / 1000)));

          return c.json({
            errcode: 'M_LIMIT_EXCEEDED',
            error: 'Too many requests',
            retry_after_ms: retryAfter * 1000,
          }, 429);
        }

        // Increment count
        data.count++;
        await c.env.CACHE.put(key, JSON.stringify(data), {
          expirationTtl: Math.ceil(config.windowMs / 1000) + 1,
        });

        // Set rate limit headers
        c.header('X-RateLimit-Limit', String(config.requests));
        c.header('X-RateLimit-Remaining', String(config.requests - data.count));
        c.header('X-RateLimit-Reset', String(Math.ceil((data.firstRequest + config.windowMs) / 1000)));
      } else {
        // Window expired, start new window
        await c.env.CACHE.put(key, JSON.stringify({ count: 1, firstRequest: now }), {
          expirationTtl: Math.ceil(config.windowMs / 1000) + 1,
        });

        c.header('X-RateLimit-Limit', String(config.requests));
        c.header('X-RateLimit-Remaining', String(config.requests - 1));
        c.header('X-RateLimit-Reset', String(Math.ceil((now + config.windowMs) / 1000)));
      }
    } else {
      // First request in window
      await c.env.CACHE.put(key, JSON.stringify({ count: 1, firstRequest: now }), {
        expirationTtl: Math.ceil(config.windowMs / 1000) + 1,
      });

      c.header('X-RateLimit-Limit', String(config.requests));
      c.header('X-RateLimit-Remaining', String(config.requests - 1));
      c.header('X-RateLimit-Reset', String(Math.ceil((now + config.windowMs) / 1000)));
    }
  } catch (error) {
    // If rate limiting fails, allow the request (fail open)
    console.error('Rate limiting error:', error);
  }

  return next();
  */ // End of disabled rate limiting code
}

// Stricter rate limiter for specific endpoints (can be used as route-specific middleware)
export function strictRateLimit(requests: number, windowMs: number) {
  return async (c: Context<AppEnv>, next: Next) => {
    const clientId = getClientId(c);
    const path = c.req.path;
    const key = `ratelimit:strict:${path}:${clientId}`;
    const now = Date.now();
    const windowStart = now - windowMs;

    try {
      const cached = await c.env.CACHE.get(key);

      if (cached) {
        const data = JSON.parse(cached) as { count: number; firstRequest: number };

        if (data.firstRequest > windowStart && data.count >= requests) {
          const retryAfter = Math.ceil((data.firstRequest + windowMs - now) / 1000);

          c.header('Retry-After', String(retryAfter));

          return c.json({
            errcode: 'M_LIMIT_EXCEEDED',
            error: 'Too many requests',
            retry_after_ms: retryAfter * 1000,
          }, 429);
        }

        if (data.firstRequest > windowStart) {
          data.count++;
          await c.env.CACHE.put(key, JSON.stringify(data), {
            expirationTtl: Math.ceil(windowMs / 1000) + 1,
          });
        } else {
          await c.env.CACHE.put(key, JSON.stringify({ count: 1, firstRequest: now }), {
            expirationTtl: Math.ceil(windowMs / 1000) + 1,
          });
        }
      } else {
        await c.env.CACHE.put(key, JSON.stringify({ count: 1, firstRequest: now }), {
          expirationTtl: Math.ceil(windowMs / 1000) + 1,
        });
      }
    } catch (error) {
      console.error('Strict rate limiting error:', error);
    }

    return next();
  };
}
