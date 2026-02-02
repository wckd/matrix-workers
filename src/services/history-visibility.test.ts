// Tests for history visibility enforcement
import { describe, it, expect } from 'vitest';
import { canSeeEvent, filterEventsByVisibility, type VisibilityContext } from './history-visibility';

describe('History visibility enforcement', () => {
  const baseEvent = { origin_server_ts: 1000 };

  describe('canSeeEvent', () => {
    describe('world_readable visibility', () => {
      const context: VisibilityContext = {
        visibility: 'world_readable',
        isMember: false,
        wasEverMember: false,
      };

      it('should allow anyone to see events', () => {
        expect(canSeeEvent(baseEvent, context)).toBe(true);
      });

      it('should allow non-members to see events', () => {
        expect(canSeeEvent(baseEvent, { ...context, wasEverMember: false })).toBe(true);
      });
    });

    describe('shared visibility', () => {
      it('should allow current members to see all events', () => {
        const context: VisibilityContext = {
          visibility: 'shared',
          isMember: true,
          wasEverMember: true,
          joinedAt: 500,
        };
        expect(canSeeEvent({ origin_server_ts: 100 }, context)).toBe(true); // Before join
        expect(canSeeEvent({ origin_server_ts: 1000 }, context)).toBe(true); // After join
      });

      it('should allow past members to see all events', () => {
        const context: VisibilityContext = {
          visibility: 'shared',
          isMember: false, // Left the room
          wasEverMember: true,
          joinedAt: 500,
        };
        expect(canSeeEvent({ origin_server_ts: 100 }, context)).toBe(true);
      });

      it('should deny non-members', () => {
        const context: VisibilityContext = {
          visibility: 'shared',
          isMember: false,
          wasEverMember: false,
        };
        expect(canSeeEvent(baseEvent, context)).toBe(false);
      });
    });

    describe('invited visibility', () => {
      it('should allow seeing events from invite time onwards', () => {
        const context: VisibilityContext = {
          visibility: 'invited',
          isMember: true,
          wasEverMember: true,
          invitedAt: 500,
          joinedAt: 600,
        };
        expect(canSeeEvent({ origin_server_ts: 400 }, context)).toBe(false); // Before invite
        expect(canSeeEvent({ origin_server_ts: 500 }, context)).toBe(true); // At invite
        expect(canSeeEvent({ origin_server_ts: 1000 }, context)).toBe(true); // After invite
      });

      it('should use join time if no invite time (direct join)', () => {
        const context: VisibilityContext = {
          visibility: 'invited',
          isMember: true,
          wasEverMember: true,
          joinedAt: 600,
        };
        expect(canSeeEvent({ origin_server_ts: 500 }, context)).toBe(false);
        expect(canSeeEvent({ origin_server_ts: 600 }, context)).toBe(true);
      });

      it('should deny non-members', () => {
        const context: VisibilityContext = {
          visibility: 'invited',
          isMember: false,
          wasEverMember: false,
        };
        expect(canSeeEvent(baseEvent, context)).toBe(false);
      });
    });

    describe('joined visibility', () => {
      it('should allow seeing events from join time onwards', () => {
        const context: VisibilityContext = {
          visibility: 'joined',
          isMember: true,
          wasEverMember: true,
          invitedAt: 400,
          joinedAt: 600,
        };
        expect(canSeeEvent({ origin_server_ts: 500 }, context)).toBe(false); // After invite but before join
        expect(canSeeEvent({ origin_server_ts: 600 }, context)).toBe(true); // At join
        expect(canSeeEvent({ origin_server_ts: 1000 }, context)).toBe(true); // After join
      });

      it('should deny if user never joined', () => {
        const context: VisibilityContext = {
          visibility: 'joined',
          isMember: false,
          wasEverMember: true,
          invitedAt: 400, // Only invited, never joined
        };
        expect(canSeeEvent(baseEvent, context)).toBe(false);
      });

      it('should deny non-members', () => {
        const context: VisibilityContext = {
          visibility: 'joined',
          isMember: false,
          wasEverMember: false,
        };
        expect(canSeeEvent(baseEvent, context)).toBe(false);
      });
    });
  });

  describe('filterEventsByVisibility', () => {
    const events = [
      { origin_server_ts: 100, event_id: '$e1' },
      { origin_server_ts: 200, event_id: '$e2' },
      { origin_server_ts: 300, event_id: '$e3' },
      { origin_server_ts: 400, event_id: '$e4' },
      { origin_server_ts: 500, event_id: '$e5' },
    ];

    it('should return all events for world_readable', () => {
      const context: VisibilityContext = {
        visibility: 'world_readable',
        isMember: false,
        wasEverMember: false,
      };
      const result = filterEventsByVisibility(events, context);
      expect(result).toHaveLength(5);
    });

    it('should return all events for shared with member', () => {
      const context: VisibilityContext = {
        visibility: 'shared',
        isMember: true,
        wasEverMember: true,
        joinedAt: 300,
      };
      const result = filterEventsByVisibility(events, context);
      expect(result).toHaveLength(5);
    });

    it('should filter events for joined visibility', () => {
      const context: VisibilityContext = {
        visibility: 'joined',
        isMember: true,
        wasEverMember: true,
        joinedAt: 300,
      };
      const result = filterEventsByVisibility(events, context);
      expect(result).toHaveLength(3);
      expect(result.map(e => e.event_id)).toEqual(['$e3', '$e4', '$e5']);
    });

    it('should filter events for invited visibility', () => {
      const context: VisibilityContext = {
        visibility: 'invited',
        isMember: true,
        wasEverMember: true,
        invitedAt: 200,
        joinedAt: 300,
      };
      const result = filterEventsByVisibility(events, context);
      expect(result).toHaveLength(4);
      expect(result.map(e => e.event_id)).toEqual(['$e2', '$e3', '$e4', '$e5']);
    });

    it('should return empty array for non-members with shared visibility', () => {
      const context: VisibilityContext = {
        visibility: 'shared',
        isMember: false,
        wasEverMember: false,
      };
      const result = filterEventsByVisibility(events, context);
      expect(result).toHaveLength(0);
    });

    it('should handle empty events array', () => {
      const context: VisibilityContext = {
        visibility: 'joined',
        isMember: true,
        wasEverMember: true,
        joinedAt: 300,
      };
      const result = filterEventsByVisibility([], context);
      expect(result).toHaveLength(0);
    });
  });
});
