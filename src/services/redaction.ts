// Redaction content stripping per Matrix spec
// https://spec.matrix.org/v1.12/client-server-api/#redactions

import type { PDU, MatrixEvent } from '../types';

/**
 * Fields preserved in redacted events (top-level)
 * Reference for Matrix spec compliance - these fields are kept when stripping redacted events
 */
const _PRESERVED_TOP_LEVEL_FIELDS = [
  'event_id',
  'type',
  'room_id',
  'sender',
  'state_key',
  'content',
  'hashes',
  'signatures',
  'depth',
  'prev_events',
  'auth_events',
  'origin_server_ts',
  'origin',
  'unsigned',
] as const;
void _PRESERVED_TOP_LEVEL_FIELDS; // Referenced for documentation purposes

/**
 * Content fields preserved for specific event types
 */
const PRESERVED_CONTENT_FIELDS: Record<string, Set<string>> = {
  'm.room.member': new Set(['membership']),
  'm.room.create': new Set(['creator']),
  'm.room.join_rules': new Set(['join_rule']),
  'm.room.power_levels': new Set([
    'ban',
    'events',
    'events_default',
    'kick',
    'redact',
    'state_default',
    'users',
    'users_default',
  ]),
  'm.room.history_visibility': new Set(['history_visibility']),
};

/**
 * Get the stripped content for a redacted event based on its type
 */
export function getRedactedContent(
  eventType: string,
  originalContent: Record<string, unknown>
): Record<string, unknown> {
  const preservedFields = PRESERVED_CONTENT_FIELDS[eventType];

  if (!preservedFields) {
    // All other event types have their content replaced with empty object
    return {};
  }

  // Keep only the preserved fields
  const strippedContent: Record<string, unknown> = {};
  for (const field of preservedFields) {
    if (field in originalContent) {
      strippedContent[field] = originalContent[field];
    }
  }

  return strippedContent;
}

/**
 * Strip a PDU/event to its redacted form
 *
 * @param event - The event to strip
 * @param redactionEvent - The m.room.redaction event that redacted this event
 * @returns The stripped event with unsigned.redacted_because set
 */
export function stripRedactedEvent<T extends PDU | MatrixEvent>(
  event: T,
  redactionEvent: PDU | MatrixEvent
): T {
  // Strip content based on event type
  const strippedContent = getRedactedContent(event.type, event.content);

  // Build the redacted event
  const redactedEvent: T = {
    ...event,
    content: strippedContent,
    unsigned: {
      ...event.unsigned,
      redacted_because: redactionEvent,
    },
  };

  return redactedEvent;
}

/**
 * Apply redaction to an event if it has been redacted
 *
 * @param event - The event that might be redacted
 * @param redactedBecause - The event ID of the redaction event, or null if not redacted
 * @param getRedactionEvent - Function to fetch the redaction event by ID
 * @returns The event (stripped if redacted), or the original event
 */
export async function applyRedactionIfNeeded<T extends PDU | MatrixEvent>(
  event: T,
  redactedBecause: string | null,
  getRedactionEvent: (eventId: string) => Promise<PDU | null>
): Promise<T> {
  if (!redactedBecause) {
    return event;
  }

  const redactionEvent = await getRedactionEvent(redactedBecause);
  if (!redactionEvent) {
    // Redaction event not found - shouldn't happen, but return original
    console.warn(`[redaction] Redaction event ${redactedBecause} not found for event ${event.event_id}`);
    return event;
  }

  return stripRedactedEvent(event, redactionEvent);
}

/**
 * Apply redactions to a list of events
 *
 * @param events - Array of events with their redaction status
 * @param getRedactionEvent - Function to fetch redaction events
 * @returns Array of events with redaction applied where needed
 */
export async function applyRedactionsToEvents<T extends PDU | MatrixEvent>(
  events: Array<{ event: T; redactedBecause: string | null }>,
  getRedactionEvent: (eventId: string) => Promise<PDU | null>
): Promise<T[]> {
  // Collect unique redaction event IDs
  const redactionIds = new Set<string>();
  for (const { redactedBecause } of events) {
    if (redactedBecause) {
      redactionIds.add(redactedBecause);
    }
  }

  // Fetch all redaction events in parallel
  const redactionEventsMap = new Map<string, PDU | null>();
  await Promise.all(
    Array.from(redactionIds).map(async (id) => {
      const redactionEvent = await getRedactionEvent(id);
      redactionEventsMap.set(id, redactionEvent);
    })
  );

  // Apply redactions
  return events.map(({ event, redactedBecause }) => {
    if (!redactedBecause) {
      return event;
    }

    const redactionEvent = redactionEventsMap.get(redactedBecause);
    if (!redactionEvent) {
      console.warn(`[redaction] Redaction event ${redactedBecause} not found for event ${event.event_id}`);
      return event;
    }

    return stripRedactedEvent(event, redactionEvent);
  });
}
