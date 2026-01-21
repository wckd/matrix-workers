// Transaction ID Service
// Implements: https://spec.matrix.org/v1.12/client-server-api/#transaction-identifiers
//
// Transaction IDs ensure idempotency for PUT requests. If a client sends
// the same request twice with the same txnId, the server returns the
// cached response instead of processing again.
//
// This is critical for:
// - Sending messages (PUT /rooms/:roomId/send/:eventType/:txnId)
// - To-device messages (PUT /sendToDevice/:eventType/:txnId)
// - State events (PUT /rooms/:roomId/state/:eventType/:stateKey)
// - Redactions (PUT /rooms/:roomId/redact/:eventId/:txnId)

// Types used locally

export interface TransactionResult {
  eventId?: string;
  response?: any;
}

/**
 * Check if a transaction has already been processed
 * Returns the cached result if found, null otherwise
 */
export async function getTransaction(
  db: D1Database,
  userId: string,
  txnId: string
): Promise<TransactionResult | null> {
  const result = await db.prepare(`
    SELECT event_id, response FROM transaction_ids
    WHERE user_id = ? AND txn_id = ?
  `).bind(userId, txnId).first<{
    event_id: string | null;
    response: string | null;
  }>();

  if (!result) {
    return null;
  }

  return {
    eventId: result.event_id || undefined,
    response: result.response ? JSON.parse(result.response) : undefined,
  };
}

/**
 * Store a transaction result for idempotency
 */
export async function storeTransaction(
  db: D1Database,
  userId: string,
  txnId: string,
  eventId?: string,
  response?: any
): Promise<void> {
  await db.prepare(`
    INSERT INTO transaction_ids (user_id, txn_id, event_id, response)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (user_id, txn_id) DO UPDATE SET
      event_id = COALESCE(excluded.event_id, transaction_ids.event_id),
      response = COALESCE(excluded.response, transaction_ids.response)
  `).bind(
    userId,
    txnId,
    eventId || null,
    response ? JSON.stringify(response) : null
  ).run();
}

/**
 * Clean up old transactions (should be called periodically)
 * Default retention: 24 hours
 */
export async function cleanupOldTransactions(
  db: D1Database,
  maxAgeMs: number = 24 * 60 * 60 * 1000
): Promise<number> {
  const cutoff = Date.now() - maxAgeMs;

  const result = await db.prepare(`
    DELETE FROM transaction_ids WHERE created_at < ?
  `).bind(cutoff).run();

  return result.meta.changes || 0;
}

/**
 * Helper to handle transaction checking in a request handler
 * Returns the cached response if transaction exists, null to continue processing
 */
export async function checkTransactionIdempotency(
  db: D1Database,
  userId: string,
  txnId: string | undefined
): Promise<{ cached: true; response: any } | { cached: false }> {
  if (!txnId) {
    return { cached: false };
  }

  const existing = await getTransaction(db, userId, txnId);
  if (existing) {
    // Return cached response or construct from eventId
    const response = existing.response || (existing.eventId ? { event_id: existing.eventId } : {});
    return { cached: true, response };
  }

  return { cached: false };
}

/**
 * Higher-order function for idempotent request handling
 * Wraps a handler to automatically check/store transaction IDs
 */
export function withIdempotency<T>(
  handler: () => Promise<{ eventId?: string; response: T }>
) {
  return async (
    db: D1Database,
    userId: string,
    txnId: string | undefined
  ): Promise<T> => {
    // Check for existing transaction
    if (txnId) {
      const existing = await getTransaction(db, userId, txnId);
      if (existing?.response) {
        return existing.response as T;
      }
    }

    // Execute handler
    const result = await handler();

    // Store transaction
    if (txnId) {
      await storeTransaction(db, userId, txnId, result.eventId, result.response);
    }

    return result.response;
  };
}
