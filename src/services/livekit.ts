// LiveKit JWT Service for MatrixRTC (MSC4195)
// Generates access tokens for LiveKit SFU

import type { Env } from '../types';

// LiveKit JWT header and payload types
interface LiveKitGrant {
  roomJoin?: boolean;
  roomCreate?: boolean;
  room?: string;
  canPublish?: boolean;
  canSubscribe?: boolean;
  canPublishData?: boolean;
  hidden?: boolean;
  recorder?: boolean;
}

interface LiveKitClaims {
  iss: string; // API Key
  sub: string; // Participant identity
  nbf: number; // Not before (Unix timestamp)
  exp: number; // Expiration (Unix timestamp)
  video?: LiveKitGrant;
  metadata?: string;
  name?: string;
}

// Base64URL encode (no padding)
function base64UrlEncode(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Create HMAC-SHA256 signature
async function signHS256(data: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return base64UrlEncode(new Uint8Array(signature));
}

// Generate a LiveKit JWT token
export async function generateLiveKitToken(
  apiKey: string,
  apiSecret: string,
  roomName: string,
  participantIdentity: string,
  participantName?: string,
  ttlSeconds: number = 3600
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  const claims: LiveKitClaims = {
    iss: apiKey,
    sub: participantIdentity,
    nbf: now,
    exp: now + ttlSeconds,
    video: {
      roomJoin: true,
      room: roomName,
      canPublish: true,
      canSubscribe: true,
      canPublishData: true,
    },
    name: participantName || participantIdentity,
  };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const claimsB64 = base64UrlEncode(JSON.stringify(claims));
  const signature = await signHS256(`${headerB64}.${claimsB64}`, apiSecret);

  return `${headerB64}.${claimsB64}.${signature}`;
}

// LiveKit configuration
export interface LiveKitConfig {
  apiKey: string;
  apiSecret: string;
  wsUrl: string; // WebSocket URL for clients to connect to
}

// Get LiveKit config from environment
export function getLiveKitConfig(env: Env): LiveKitConfig | null {
  const apiKey = env.LIVEKIT_API_KEY;
  const apiSecret = env.LIVEKIT_API_SECRET;
  const wsUrl = env.LIVEKIT_URL;

  if (!apiKey || !apiSecret || !wsUrl) {
    return null;
  }

  return { apiKey, apiSecret, wsUrl };
}

// Create a room via LiveKit API (through VPC)
export async function createLiveKitRoom(
  env: Env,
  roomName: string
): Promise<{ room: { name: string; sid: string } } | null> {
  try {
    // LiveKit uses Twirp protocol
    const response = await env.LIVEKIT_API.fetch(
      'http://localhost:7880/twirp/livekit.RoomService/CreateRoom',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: roomName }),
      }
    );

    if (!response.ok) {
      console.error('Failed to create LiveKit room:', await response.text());
      return null;
    }

    return await response.json();
  } catch (error) {
    console.error('Error creating LiveKit room:', error);
    return null;
  }
}

// List rooms via LiveKit API
export async function listLiveKitRooms(env: Env): Promise<{ rooms: any[] } | null> {
  try {
    const response = await env.LIVEKIT_API.fetch(
      'http://localhost:7880/twirp/livekit.RoomService/ListRooms',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      }
    );

    if (!response.ok) {
      console.error('Failed to list LiveKit rooms:', await response.text());
      return null;
    }

    return await response.json();
  } catch (error) {
    console.error('Error listing LiveKit rooms:', error);
    return null;
  }
}
