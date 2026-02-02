// Tests for event validation
import { describe, it, expect } from 'vitest';
import {
  isValidUserId,
  isValidRoomId,
  isValidEventId,
  extractServerName,
  validateEventFields,
  validatePduFields,
  validateStateEventFields,
} from './event-validation';

describe('Matrix ID validation', () => {
  describe('isValidUserId', () => {
    it('should accept valid user IDs', () => {
      expect(isValidUserId('@alice:example.com')).toBe(true);
      expect(isValidUserId('@bob:matrix.org')).toBe(true);
      expect(isValidUserId('@user123:server.io')).toBe(true);
      expect(isValidUserId('@test_user:localhost')).toBe(true);
      expect(isValidUserId('@a:b')).toBe(true);
      expect(isValidUserId('@user:server:8448')).toBe(true);
    });

    it('should reject invalid user IDs', () => {
      expect(isValidUserId('alice:example.com')).toBe(false); // Missing @
      expect(isValidUserId('@alice')).toBe(false); // Missing domain
      expect(isValidUserId('@:example.com')).toBe(false); // Empty localpart
      expect(isValidUserId('not a user id')).toBe(false);
      expect(isValidUserId('')).toBe(false);
      expect(isValidUserId(null)).toBe(false);
      expect(isValidUserId(undefined)).toBe(false);
      expect(isValidUserId(123)).toBe(false);
    });
  });

  describe('isValidRoomId', () => {
    it('should accept valid room IDs', () => {
      expect(isValidRoomId('!abc123:example.com')).toBe(true);
      expect(isValidRoomId('!opaque_id:matrix.org')).toBe(true);
      expect(isValidRoomId('!a:b')).toBe(true);
      expect(isValidRoomId('!room:server:8448')).toBe(true);
    });

    it('should reject invalid room IDs', () => {
      expect(isValidRoomId('abc123:example.com')).toBe(false); // Missing !
      expect(isValidRoomId('!abc123')).toBe(false); // Missing domain
      expect(isValidRoomId('!:example.com')).toBe(false); // Empty opaque ID
      expect(isValidRoomId('@user:example.com')).toBe(false); // Wrong prefix
      expect(isValidRoomId('')).toBe(false);
      expect(isValidRoomId(null)).toBe(false);
    });
  });

  describe('isValidEventId', () => {
    it('should accept valid event IDs', () => {
      expect(isValidEventId('$abc123')).toBe(true);
      expect(isValidEventId('$eventid_with_underscore')).toBe(true);
      expect(isValidEventId('$YWJjZGVm')).toBe(true); // Base64-like
      expect(isValidEventId('$a')).toBe(true);
    });

    it('should reject invalid event IDs', () => {
      expect(isValidEventId('abc123')).toBe(false); // Missing $
      expect(isValidEventId('$')).toBe(false); // Empty after $
      expect(isValidEventId('')).toBe(false);
      expect(isValidEventId(null)).toBe(false);
    });
  });

  describe('extractServerName', () => {
    it('should extract server name from user ID', () => {
      expect(extractServerName('@alice:example.com')).toBe('example.com');
      expect(extractServerName('@bob:matrix.org')).toBe('matrix.org');
      expect(extractServerName('@user:server:8448')).toBe('server:8448');
    });

    it('should return null for invalid user IDs', () => {
      expect(extractServerName('invalid')).toBe(null);
      expect(extractServerName('@noserver')).toBe(null);
    });
  });
});

describe('Event field validation', () => {
  describe('validateEventFields', () => {
    const validEvent = {
      type: 'm.room.message',
      sender: '@alice:example.com',
      room_id: '!room:example.com',
      origin_server_ts: 1234567890123,
      content: { body: 'Hello' },
    };

    it('should accept valid events', () => {
      expect(validateEventFields(validEvent)).toEqual({ valid: true });
    });

    it('should reject events with missing type', () => {
      const event = { ...validEvent, type: undefined };
      const result = validateEventFields(event as any);
      expect(result.valid).toBe(false);
      expect(result.errcode).toBe('M_BAD_JSON');
    });

    it('should reject events with empty type', () => {
      const event = { ...validEvent, type: '' };
      const result = validateEventFields(event);
      expect(result.valid).toBe(false);
    });

    it('should reject events with invalid sender', () => {
      const event = { ...validEvent, sender: 'invalid' };
      const result = validateEventFields(event);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('sender');
    });

    it('should reject events with invalid room_id', () => {
      const event = { ...validEvent, room_id: 'invalid' };
      const result = validateEventFields(event);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('room_id');
    });

    it('should reject events with invalid origin_server_ts', () => {
      expect(validateEventFields({ ...validEvent, origin_server_ts: -1 }).valid).toBe(false);
      expect(validateEventFields({ ...validEvent, origin_server_ts: 'string' } as any).valid).toBe(false);
      expect(validateEventFields({ ...validEvent, origin_server_ts: 1.5 }).valid).toBe(false);
    });

    it('should reject events with invalid content', () => {
      expect(validateEventFields({ ...validEvent, content: null }).valid).toBe(false);
      expect(validateEventFields({ ...validEvent, content: 'string' } as any).valid).toBe(false);
      expect(validateEventFields({ ...validEvent, content: [] }).valid).toBe(false);
    });
  });

  describe('validatePduFields', () => {
    const validPdu = {
      type: 'm.room.message',
      sender: '@alice:example.com',
      room_id: '!room:example.com',
      origin_server_ts: 1234567890123,
      content: { body: 'Hello' },
      event_id: '$event123',
      depth: 5,
      auth_events: ['$auth1', '$auth2'],
      prev_events: ['$prev1'],
    };

    it('should accept valid PDUs', () => {
      expect(validatePduFields(validPdu)).toEqual({ valid: true });
    });

    it('should reject PDUs with invalid event_id', () => {
      const pdu = { ...validPdu, event_id: 'invalid' };
      const result = validatePduFields(pdu);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('event_id');
    });

    it('should reject PDUs with invalid depth', () => {
      expect(validatePduFields({ ...validPdu, depth: -1 }).valid).toBe(false);
      expect(validatePduFields({ ...validPdu, depth: 'string' } as any).valid).toBe(false);
    });

    it('should reject PDUs with invalid auth_events', () => {
      expect(validatePduFields({ ...validPdu, auth_events: 'not array' } as any).valid).toBe(false);
      expect(validatePduFields({ ...validPdu, auth_events: ['invalid'] }).valid).toBe(false);
    });

    it('should reject PDUs with invalid prev_events', () => {
      expect(validatePduFields({ ...validPdu, prev_events: 'not array' } as any).valid).toBe(false);
      expect(validatePduFields({ ...validPdu, prev_events: ['invalid'] }).valid).toBe(false);
    });

    it('should accept PDUs with empty auth_events and prev_events', () => {
      const pdu = { ...validPdu, auth_events: [], prev_events: [] };
      expect(validatePduFields(pdu)).toEqual({ valid: true });
    });
  });

  describe('validateStateEventFields', () => {
    const validStateEvent = {
      type: 'm.room.name',
      sender: '@alice:example.com',
      room_id: '!room:example.com',
      origin_server_ts: 1234567890123,
      content: { name: 'Test Room' },
      state_key: '',
    };

    it('should accept valid state events', () => {
      expect(validateStateEventFields(validStateEvent)).toEqual({ valid: true });
    });

    it('should accept state events with non-empty state_key', () => {
      const event = { ...validStateEvent, state_key: '@user:example.com' };
      expect(validateStateEventFields(event)).toEqual({ valid: true });
    });

    it('should reject state events without state_key', () => {
      const event = { ...validStateEvent, state_key: undefined };
      const result = validateStateEventFields(event as any);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('state_key');
    });

    it('should reject state events with non-string state_key', () => {
      const event = { ...validStateEvent, state_key: 123 };
      const result = validateStateEventFields(event as any);
      expect(result.valid).toBe(false);
    });
  });
});
