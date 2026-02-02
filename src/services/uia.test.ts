// Tests for User-Interactive Authentication (UIA) service
import { describe, it, expect } from 'vitest';
import {
  isUiaComplete,
  buildUiaResponse,
  StandardFlows,
  type UiaSession,
  type UiaFlow,
} from './uia';

describe('UIA service', () => {
  describe('isUiaComplete', () => {
    it('should return true when all stages of a flow are completed', () => {
      const session: UiaSession = {
        session_id: 'test123',
        type: 'registration',
        flows: [{ stages: ['m.login.dummy'] }],
        completed_stages: ['m.login.dummy'],
        params: {},
        created_at: Date.now(),
      };
      expect(isUiaComplete(session)).toBe(true);
    });

    it('should return true when any flow is fully completed', () => {
      const session: UiaSession = {
        session_id: 'test123',
        type: 'registration',
        flows: [
          { stages: ['m.login.recaptcha', 'm.login.terms'] },
          { stages: ['m.login.dummy'] },
        ],
        completed_stages: ['m.login.dummy'],
        params: {},
        created_at: Date.now(),
      };
      expect(isUiaComplete(session)).toBe(true);
    });

    it('should return false when no flow is fully completed', () => {
      const session: UiaSession = {
        session_id: 'test123',
        type: 'registration',
        flows: [
          { stages: ['m.login.recaptcha', 'm.login.terms'] },
          { stages: ['m.login.password'] },
        ],
        completed_stages: ['m.login.recaptcha'],
        params: {},
        created_at: Date.now(),
      };
      expect(isUiaComplete(session)).toBe(false);
    });

    it('should return false when no stages are completed', () => {
      const session: UiaSession = {
        session_id: 'test123',
        type: 'password_change',
        flows: [{ stages: ['m.login.password'] }],
        completed_stages: [],
        params: {},
        created_at: Date.now(),
      };
      expect(isUiaComplete(session)).toBe(false);
    });

    it('should handle multi-stage flows correctly', () => {
      const session: UiaSession = {
        session_id: 'test123',
        type: 'registration',
        flows: [{ stages: ['m.login.recaptcha', 'm.login.terms', 'm.login.email.identity'] }],
        completed_stages: ['m.login.recaptcha', 'm.login.terms'],
        params: {},
        created_at: Date.now(),
      };
      expect(isUiaComplete(session)).toBe(false);

      session.completed_stages.push('m.login.email.identity');
      expect(isUiaComplete(session)).toBe(true);
    });
  });

  describe('buildUiaResponse', () => {
    it('should build response without completed stages when empty', () => {
      const session: UiaSession = {
        session_id: 'abc123',
        type: 'registration',
        flows: [{ stages: ['m.login.dummy'] }],
        completed_stages: [],
        params: {},
        created_at: Date.now(),
      };

      const response = buildUiaResponse(session);
      expect(response).toEqual({
        flows: [{ stages: ['m.login.dummy'] }],
        params: {},
        session: 'abc123',
      });
      expect(response.completed).toBeUndefined();
    });

    it('should include completed stages when present', () => {
      const session: UiaSession = {
        session_id: 'abc123',
        type: 'registration',
        flows: [{ stages: ['m.login.recaptcha', 'm.login.terms'] }],
        completed_stages: ['m.login.recaptcha'],
        params: {},
        created_at: Date.now(),
      };

      const response = buildUiaResponse(session);
      expect(response.completed).toEqual(['m.login.recaptcha']);
    });

    it('should include params in response', () => {
      const session: UiaSession = {
        session_id: 'abc123',
        type: 'registration',
        flows: [{ stages: ['m.login.recaptcha'] }],
        completed_stages: [],
        params: {
          'm.login.recaptcha': {
            public_key: 'test-key-123',
          },
        },
        created_at: Date.now(),
      };

      const response = buildUiaResponse(session);
      expect(response.params).toEqual({
        'm.login.recaptcha': {
          public_key: 'test-key-123',
        },
      });
    });

    it('should include all flows in response', () => {
      const flows: UiaFlow[] = [
        { stages: ['m.login.recaptcha', 'm.login.terms'] },
        { stages: ['m.login.password'] },
        { stages: ['m.login.dummy'] },
      ];
      const session: UiaSession = {
        session_id: 'abc123',
        type: 'registration',
        flows,
        completed_stages: [],
        params: {},
        created_at: Date.now(),
      };

      const response = buildUiaResponse(session);
      expect(response.flows).toEqual(flows);
    });
  });

  describe('StandardFlows', () => {
    it('should return registration flow with dummy stage', () => {
      const flows = StandardFlows.registration;
      expect(flows).toEqual([{ stages: ['m.login.dummy'] }]);
    });

    it('should return password required flow', () => {
      const flows = StandardFlows.passwordRequired;
      expect(flows).toEqual([{ stages: ['m.login.password'] }]);
    });

    it('should return dummy only flow', () => {
      const flows = StandardFlows.dummyOnly;
      expect(flows).toEqual([{ stages: ['m.login.dummy'] }]);
    });

    it('should return mutable arrays (not frozen)', () => {
      const flows = StandardFlows.registration;
      // Should be able to push without error
      expect(() => flows.push({ stages: ['m.login.test'] })).not.toThrow();
    });

    it('should return new array instances each time', () => {
      const flows1 = StandardFlows.registration;
      const flows2 = StandardFlows.registration;
      expect(flows1).not.toBe(flows2); // Different instances
      expect(flows1).toEqual(flows2); // Same content
    });
  });
});
