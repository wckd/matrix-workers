// Idempotency Middleware
// Implements: https://spec.matrix.org/v1.12/client-server-api/#transaction-identifiers
//
// This middleware intercepts PUT requests with txnId parameters and:
// 1. Checks if the transaction was already processed
// 2. Returns cached response if found
// 3. After handler completes, stores the response for future requests

import type { Context, Next } from 'hono';
import type { AppEnv } from '../types';
import { getTransaction, storeTransaction } from '../services/transactions';

/**
 * Middleware that handles transaction ID idempotency
 * Use on PUT endpoints that include :txnId in their path
 */
export function idempotent() {
  return async (c: Context<AppEnv>, next: Next) => {
    const txnId = c.req.param('txnId');
    const userId = c.get('userId');

    if (!txnId || !userId) {
      // No transaction ID or not authenticated, continue normally
      return next();
    }

    const db = c.env.DB;

    // Check for existing transaction
    const existing = await getTransaction(db, userId, txnId);
    if (existing) {
      // Return cached response
      if (existing.response) {
        return c.json(existing.response);
      }
      if (existing.eventId) {
        return c.json({ event_id: existing.eventId });
      }
      return c.json({});
    }

    // Continue with handler
    await next();

    // After handler, try to extract and store response
    // Note: This is tricky because we've already sent the response
    // The better approach is to have handlers call storeTransaction directly
    // This middleware is mainly for the pre-check
  };
}

/**
 * Helper to create an idempotent response
 * Call this in your handler instead of c.json() to automatically handle idempotency
 */
export async function idempotentResponse(
  c: Context<AppEnv>,
  response: Record<string, unknown>,
  eventId?: string
) {
  const txnId = c.req.param('txnId');
  const userId = c.get('userId');
  const db = c.env.DB;

  if (txnId && userId) {
    await storeTransaction(db, userId, txnId, eventId, response);
  }

  return c.json(response);
}
