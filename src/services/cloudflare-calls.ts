// Cloudflare Calls SFU Service
// Provides WebRTC-based video/audio calling using Cloudflare's global SFU network
// API Reference: https://developers.cloudflare.com/realtime/sfu/

import type { Env } from '../types';

const CALLS_API_BASE = 'https://rtc.live.cloudflare.com/v1';

export interface SessionDescription {
  sdp: string;
  type: 'offer' | 'answer';
}

export interface TrackObject {
  location: 'local' | 'remote';
  mid?: string;
  trackName?: string;
  sessionId?: string; // Required for remote tracks
}

export interface NewSessionResponse {
  sessionId: string;
  sessionDescription?: SessionDescription;
}

export interface NewTracksRequest {
  sessionDescription?: SessionDescription;
  tracks: TrackObject[];
}

export interface TrackResult {
  mid: string;
  trackName: string;
  errorCode?: string;
  errorDescription?: string;
}

export interface NewTracksResponse {
  sessionDescription?: SessionDescription;
  tracks: TrackResult[];
  requiresImmediateRenegotiation: boolean;
}

export interface RenegotiateRequest {
  sessionDescription: SessionDescription;
}

export interface RenegotiateResponse {
  sessionDescription?: SessionDescription;
}

export interface SessionState {
  tracks: Array<{
    trackName: string;
    mid: string;
    status: 'active' | 'inactive' | 'waiting';
    location: 'local' | 'remote';
  }>;
}

export class CloudflareCallsError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 500
  ) {
    super(message);
    this.name = 'CloudflareCallsError';
  }
}

/**
 * Check if Cloudflare Calls is configured
 */
export function isCallsConfigured(env: Env): boolean {
  return Boolean(env.CALLS_APP_ID && env.CALLS_APP_SECRET);
}

/**
 * Make an authenticated request to the Cloudflare Calls API
 */
async function callsRequest<T>(
  env: Env,
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  if (!env.CALLS_APP_ID || !env.CALLS_APP_SECRET) {
    throw new CloudflareCallsError(
      'Cloudflare Calls not configured. Set CALLS_APP_ID and CALLS_APP_SECRET.',
      'NOT_CONFIGURED',
      500
    );
  }

  const url = `${CALLS_API_BASE}/apps/${env.CALLS_APP_ID}${path}`;

  const response = await fetch(url, {
    method,
    headers: {
      'Authorization': `Bearer ${env.CALLS_APP_SECRET}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    let errorMessage = `Calls API error: ${response.status}`;
    try {
      const errorBody = await response.text();
      if (errorBody) {
        errorMessage += ` - ${errorBody}`;
      }
    } catch {
      // Ignore error reading body
    }
    throw new CloudflareCallsError(errorMessage, 'API_ERROR', response.status);
  }

  return response.json() as Promise<T>;
}

/**
 * Create a new Calls session
 * Each session corresponds to a WebRTC PeerConnection
 */
export async function createSession(env: Env): Promise<NewSessionResponse> {
  return callsRequest<NewSessionResponse>(env, 'POST', '/sessions/new');
}

/**
 * Add tracks to a session (push local tracks or pull remote tracks)
 */
export async function addTracks(
  env: Env,
  sessionId: string,
  request: NewTracksRequest
): Promise<NewTracksResponse> {
  return callsRequest<NewTracksResponse>(
    env,
    'POST',
    `/sessions/${sessionId}/tracks/new`,
    request
  );
}

/**
 * Renegotiate a session (required when requiresImmediateRenegotiation is true)
 */
export async function renegotiate(
  env: Env,
  sessionId: string,
  request: RenegotiateRequest
): Promise<RenegotiateResponse> {
  return callsRequest<RenegotiateResponse>(
    env,
    'PUT',
    `/sessions/${sessionId}/renegotiate`,
    request
  );
}

/**
 * Close tracks in a session
 */
export async function closeTracks(
  env: Env,
  sessionId: string,
  trackMids: string[],
  force: boolean = false
): Promise<void> {
  await callsRequest(
    env,
    'PUT',
    `/sessions/${sessionId}/tracks/close`,
    {
      tracks: trackMids.map(mid => ({ mid })),
      force,
    }
  );
}

/**
 * Get current session state
 */
export async function getSessionState(
  env: Env,
  sessionId: string
): Promise<SessionState> {
  return callsRequest<SessionState>(env, 'GET', `/sessions/${sessionId}`);
}

/**
 * Helper: Push a local track to the SFU
 * Returns the track info needed for others to pull it
 */
export async function pushLocalTrack(
  env: Env,
  sessionId: string,
  offer: SessionDescription,
  trackName: string
): Promise<{ answer: SessionDescription; trackName: string; mid: string }> {
  const response = await addTracks(env, sessionId, {
    sessionDescription: offer,
    tracks: [
      {
        location: 'local',
        trackName,
      },
    ],
  });

  if (!response.sessionDescription) {
    throw new CloudflareCallsError('No answer received from SFU', 'NO_ANSWER', 500);
  }

  const track = response.tracks[0];
  if (track.errorCode) {
    throw new CloudflareCallsError(
      track.errorDescription || 'Track error',
      track.errorCode,
      400
    );
  }

  return {
    answer: response.sessionDescription,
    trackName: track.trackName,
    mid: track.mid,
  };
}

/**
 * Helper: Pull a remote track from the SFU
 * Returns the offer that the client needs to answer
 */
export async function pullRemoteTrack(
  env: Env,
  sessionId: string,
  remoteSessionId: string,
  trackName: string
): Promise<{
  offer: SessionDescription;
  mid: string;
  requiresRenegotiation: boolean;
}> {
  const response = await addTracks(env, sessionId, {
    tracks: [
      {
        location: 'remote',
        sessionId: remoteSessionId,
        trackName,
      },
    ],
  });

  if (!response.sessionDescription) {
    throw new CloudflareCallsError('No offer received from SFU', 'NO_OFFER', 500);
  }

  const track = response.tracks[0];
  if (track.errorCode) {
    throw new CloudflareCallsError(
      track.errorDescription || 'Track error',
      track.errorCode,
      400
    );
  }

  return {
    offer: response.sessionDescription,
    mid: track.mid,
    requiresRenegotiation: response.requiresImmediateRenegotiation,
  };
}
