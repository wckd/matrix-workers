// Tests for redaction content stripping
import { describe, it, expect } from 'vitest';
import { getRedactedContent, stripRedactedEvent } from './redaction';

describe('Redaction content stripping', () => {
  describe('getRedactedContent', () => {
    it('should preserve membership field for m.room.member events', () => {
      const content = {
        membership: 'join',
        displayname: 'Alice',
        avatar_url: 'mxc://example.com/avatar',
        reason: 'Some reason',
      };
      const result = getRedactedContent('m.room.member', content);
      expect(result).toEqual({ membership: 'join' });
    });

    it('should preserve creator field for m.room.create events', () => {
      const content = {
        creator: '@alice:example.com',
        room_version: '10',
        'm.federate': true,
      };
      const result = getRedactedContent('m.room.create', content);
      expect(result).toEqual({ creator: '@alice:example.com' });
    });

    it('should preserve join_rule field for m.room.join_rules events', () => {
      const content = {
        join_rule: 'invite',
        allow: [{ type: 'm.room_membership', room_id: '!other:example.com' }],
      };
      const result = getRedactedContent('m.room.join_rules', content);
      expect(result).toEqual({ join_rule: 'invite' });
    });

    it('should preserve history_visibility field for m.room.history_visibility events', () => {
      const content = {
        history_visibility: 'shared',
        extra_field: 'should be stripped',
      };
      const result = getRedactedContent('m.room.history_visibility', content);
      expect(result).toEqual({ history_visibility: 'shared' });
    });

    it('should preserve multiple fields for m.room.power_levels events', () => {
      const content = {
        ban: 50,
        events: { 'm.room.name': 50 },
        events_default: 0,
        invite: 0,
        kick: 50,
        redact: 50,
        state_default: 50,
        users: { '@alice:example.com': 100 },
        users_default: 0,
        notifications: { room: 50 }, // Should be stripped
      };
      const result = getRedactedContent('m.room.power_levels', content);
      expect(result).toEqual({
        ban: 50,
        events: { 'm.room.name': 50 },
        events_default: 0,
        kick: 50,
        redact: 50,
        state_default: 50,
        users: { '@alice:example.com': 100 },
        users_default: 0,
      });
      expect(result).not.toHaveProperty('invite');
      expect(result).not.toHaveProperty('notifications');
    });

    it('should return empty object for m.room.message events', () => {
      const content = {
        msgtype: 'm.text',
        body: 'Hello, world!',
        format: 'org.matrix.custom.html',
        formatted_body: '<b>Hello</b>',
      };
      const result = getRedactedContent('m.room.message', content);
      expect(result).toEqual({});
    });

    it('should return empty object for unknown event types', () => {
      const content = {
        any: 'content',
        should: 'be stripped',
      };
      const result = getRedactedContent('m.custom.event', content);
      expect(result).toEqual({});
    });

    it('should handle missing fields gracefully', () => {
      const content = {}; // Empty content
      expect(getRedactedContent('m.room.member', content)).toEqual({});
      expect(getRedactedContent('m.room.create', content)).toEqual({});
    });
  });

  describe('stripRedactedEvent', () => {
    const baseEvent = {
      event_id: '$event123',
      type: 'm.room.message',
      room_id: '!room:example.com',
      sender: '@alice:example.com',
      origin_server_ts: 1234567890123,
      content: {
        msgtype: 'm.text',
        body: 'Hello, world!',
      },
    };

    const redactionEvent = {
      event_id: '$redaction456',
      type: 'm.room.redaction',
      room_id: '!room:example.com',
      sender: '@bob:example.com',
      origin_server_ts: 1234567890124,
      content: {
        reason: 'Inappropriate content',
      },
      redacts: '$event123',
    };

    it('should strip content and add redacted_because', () => {
      const result = stripRedactedEvent(baseEvent, redactionEvent);

      expect(result.event_id).toBe('$event123');
      expect(result.type).toBe('m.room.message');
      expect(result.sender).toBe('@alice:example.com');
      expect(result.content).toEqual({}); // Message content stripped
      expect(result.unsigned?.redacted_because).toEqual(redactionEvent);
    });

    it('should preserve membership for redacted m.room.member events', () => {
      const memberEvent = {
        ...baseEvent,
        type: 'm.room.member',
        state_key: '@alice:example.com',
        content: {
          membership: 'join',
          displayname: 'Alice',
          avatar_url: 'mxc://example.com/avatar',
        },
      };

      const result = stripRedactedEvent(memberEvent, redactionEvent);
      expect(result.content).toEqual({ membership: 'join' });
      expect(result.unsigned?.redacted_because).toEqual(redactionEvent);
    });

    it('should preserve existing unsigned data', () => {
      const eventWithUnsigned = {
        ...baseEvent,
        unsigned: {
          age: 1000,
          transaction_id: 'txn123',
        },
      };

      const result = stripRedactedEvent(eventWithUnsigned, redactionEvent);
      expect(result.unsigned?.age).toBe(1000);
      expect(result.unsigned?.transaction_id).toBe('txn123');
      expect(result.unsigned?.redacted_because).toEqual(redactionEvent);
    });

    it('should not modify the original event', () => {
      const originalContent = { ...baseEvent.content };
      stripRedactedEvent(baseEvent, redactionEvent);
      expect(baseEvent.content).toEqual(originalContent);
    });
  });
});
