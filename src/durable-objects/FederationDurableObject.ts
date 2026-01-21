// Federation Durable Object for server-to-server communication

import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../types';

interface FederationTarget {
  serverName: string;
  lastContact: number;
  retryCount: number;
  nextRetry: number | null;
}

interface OutboundEvent {
  event_id: string;
  room_id: string;
  destination: string;
  pdu: any;
  created_at: number;
  retry_count: number;
}

export class FederationDurableObject extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/send') {
      return this.handleSend(request);
    }

    if (path === '/receive') {
      return this.handleReceive(request);
    }

    if (path === '/status') {
      return this.handleStatus(request);
    }

    if (path === '/keys') {
      return this.handleKeys(request);
    }

    return new Response('Not found', { status: 404 });
  }

  // Queue an event for federation to a remote server
  private async handleSend(request: Request): Promise<Response> {
    const data = await request.json() as {
      destination: string;
      event_id: string;
      room_id: string;
      pdu: any;
    };

    const outboundEvent: OutboundEvent = {
      event_id: data.event_id,
      room_id: data.room_id,
      destination: data.destination,
      pdu: data.pdu,
      created_at: Date.now(),
      retry_count: 0,
    };

    // Store in queue
    const key = `queue:${data.destination}:${data.event_id}`;
    await this.ctx.storage.put(key, outboundEvent);

    // Try to send immediately
    await this.processFederationQueue(data.destination);

    return new Response('Queued');
  }

  // Handle incoming federation request
  private async handleReceive(request: Request): Promise<Response> {
    const origin = request.headers.get('X-Matrix-Origin');
    if (!origin) {
      return new Response(JSON.stringify({
        errcode: 'M_MISSING_PARAM',
        error: 'Missing origin header',
      }), { status: 400 });
    }

    // Verify request signature (simplified)
    // In production, verify against the server's signing keys

    const data = await request.json() as {
      pdus: any[];
      edus?: any[];
    };

    // Process incoming PDUs
    const processedPdus: string[] = [];
    for (const pdu of data.pdus || []) {
      // Store the event
      await this.ctx.storage.put(`received:${pdu.event_id}`, {
        pdu,
        origin,
        received_at: Date.now(),
      });
      processedPdus.push(pdu.event_id);
    }

    // Update server status
    const target: FederationTarget = {
      serverName: origin,
      lastContact: Date.now(),
      retryCount: 0,
      nextRetry: null,
    };
    await this.ctx.storage.put(`server:${origin}`, target);

    return new Response(JSON.stringify({
      pdus: processedPdus.reduce((acc, id) => ({ ...acc, [id]: {} }), {}),
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Get federation status for a server
  private async handleStatus(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const serverName = url.searchParams.get('server');

    if (serverName) {
      const target = await this.ctx.storage.get(`server:${serverName}`) as FederationTarget | undefined;
      return new Response(JSON.stringify(target || { serverName, status: 'unknown' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // List all known servers
    const servers: FederationTarget[] = [];
    const allKeys = await this.ctx.storage.list({ prefix: 'server:' });
    for (const [, value] of allKeys) {
      servers.push(value as FederationTarget);
    }

    return new Response(JSON.stringify({ servers }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Handle server key requests
  private async handleKeys(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const serverName = url.searchParams.get('server');

    if (!serverName) {
      return new Response(JSON.stringify({
        errcode: 'M_MISSING_PARAM',
        error: 'Missing server parameter',
      }), { status: 400 });
    }

    // Get cached keys
    const cachedKeys = await this.ctx.storage.get(`keys:${serverName}`);
    if (cachedKeys) {
      const keys = cachedKeys as { data: any; expires: number };
      if (keys.expires > Date.now()) {
        return new Response(JSON.stringify(keys.data), {
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // Fetch keys from remote server
    try {
      const response = await fetch(`https://${serverName}/_matrix/key/v2/server`, {
        headers: {
          'Accept': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();

        // Cache for 24 hours
        await this.ctx.storage.put(`keys:${serverName}`, {
          data,
          expires: Date.now() + (24 * 60 * 60 * 1000),
        });

        return new Response(JSON.stringify(data), {
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } catch (e) {
      console.error(`Failed to fetch keys from ${serverName}:`, e);
    }

    return new Response(JSON.stringify({
      errcode: 'M_NOT_FOUND',
      error: 'Server keys not found',
    }), { status: 404 });
  }

  private async processFederationQueue(destination: string): Promise<void> {
    const prefix = `queue:${destination}:`;
    const allKeys = await this.ctx.storage.list({ prefix });

    const events: OutboundEvent[] = [];
    for (const [, value] of allKeys) {
      events.push(value as OutboundEvent);
    }

    if (events.length === 0) return;

    // Sort by creation time
    events.sort((a, b) => a.created_at - b.created_at);

    // Batch events for transmission
    const pdus = events.map(e => e.pdu);

    try {
      const response = await fetch(`https://${destination}/_matrix/federation/v1/send/${Date.now()}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          // In production, add signature headers
        },
        body: JSON.stringify({
          pdus,
          edus: [],
        }),
      });

      if (response.ok) {
        // Remove sent events from queue
        for (const event of events) {
          await this.ctx.storage.delete(`queue:${destination}:${event.event_id}`);
        }

        // Update server status
        const target: FederationTarget = {
          serverName: destination,
          lastContact: Date.now(),
          retryCount: 0,
          nextRetry: null,
        };
        await this.ctx.storage.put(`server:${destination}`, target);
      } else {
        // Schedule retry
        await this.scheduleRetry(destination, events);
      }
    } catch (e) {
      console.error(`Federation send to ${destination} failed:`, e);
      await this.scheduleRetry(destination, events);
    }
  }

  private async scheduleRetry(destination: string, events: OutboundEvent[]): Promise<void> {
    const target = await this.ctx.storage.get(`server:${destination}`) as FederationTarget | undefined;
    const retryCount = (target?.retryCount || 0) + 1;

    // Exponential backoff: 1min, 2min, 4min, 8min, 16min, max 1hour
    const delay = Math.min(60000 * Math.pow(2, retryCount - 1), 3600000);
    const nextRetry = Date.now() + delay;

    // Update server status
    const newTarget: FederationTarget = {
      serverName: destination,
      lastContact: target?.lastContact || 0,
      retryCount,
      nextRetry,
    };
    await this.ctx.storage.put(`server:${destination}`, newTarget);

    // Update events with retry count
    for (const event of events) {
      event.retry_count = retryCount;
      await this.ctx.storage.put(`queue:${destination}:${event.event_id}`, event);
    }

    // Set alarm for retry
    await this.ctx.storage.setAlarm(nextRetry);
  }

  async alarm(): Promise<void> {
    // Process all destinations with pending retries
    const allKeys = await this.ctx.storage.list({ prefix: 'server:' });

    for (const [, value] of allKeys) {
      const target = value as FederationTarget;
      if (target.nextRetry && target.nextRetry <= Date.now()) {
        await this.processFederationQueue(target.serverName);
      }
    }
  }
}
