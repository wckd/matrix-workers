// Admin Durable Object for server-wide admin state and real-time updates
// Uses Durable Object storage for:
// - Server configuration (registration enabled, etc.)
// - Cached statistics (avoid D1 queries on every request)
// - Active admin sessions for real-time notifications

import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../types';

interface AdminSession {
  userId: string;
  connectedAt: number;
}

interface ServerStats {
  users: {
    total: number;
    active: number;
    registrations_24h: number;
  };
  rooms: {
    total: number;
  };
  events: {
    total: number;
    last_24h: number;
  };
  media: {
    count: number;
    total_size_bytes: number;
  };
  unresolvedReports: number;
  lastUpdated: number;
}

interface ServerConfig {
  registration_enabled: boolean;
  updated_at: number;
}

const STATS_CACHE_TTL = 30 * 1000; // 30 seconds cache for stats
const DEFAULT_CONFIG: ServerConfig = {
  registration_enabled: true,
  updated_at: 0,
};

export class AdminDurableObject extends DurableObject<Env> {
  private statsCache: ServerStats | null = null;
  private statsCacheTime: number = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    switch (path) {
      case '/config':
        return this.handleConfig(request);
      case '/stats':
        return this.handleStats(request);
      case '/websocket':
        return this.handleWebSocket(request);
      case '/broadcast':
        return this.handleBroadcast(request);
      case '/invalidate-cache':
        return this.handleInvalidateCache();
      default:
        return new Response('Not found', { status: 404 });
    }
  }

  // Server configuration management
  private async handleConfig(request: Request): Promise<Response> {
    if (request.method === 'GET') {
      const config = await this.getConfig();
      return Response.json(config);
    }

    if (request.method === 'PUT') {
      const body = await request.json() as Partial<ServerConfig>;
      const config = await this.updateConfig(body);

      // Broadcast config change to connected admins
      await this.broadcastToAdmins({
        type: 'config_changed',
        config,
      });

      return Response.json(config);
    }

    return new Response('Method not allowed', { status: 405 });
  }

  private async getConfig(): Promise<ServerConfig> {
    const stored = await this.ctx.storage.get<ServerConfig>('config');
    return stored || DEFAULT_CONFIG;
  }

  private async updateConfig(updates: Partial<ServerConfig>): Promise<ServerConfig> {
    const current = await this.getConfig();
    const newConfig: ServerConfig = {
      ...current,
      ...updates,
      updated_at: Date.now(),
    };
    await this.ctx.storage.put('config', newConfig);
    return newConfig;
  }

  // Statistics with caching
  private async handleStats(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const forceRefresh = url.searchParams.get('refresh') === 'true';

    // Check cache first
    const now = Date.now();
    if (!forceRefresh && this.statsCache && (now - this.statsCacheTime) < STATS_CACHE_TTL) {
      return Response.json(this.statsCache);
    }

    // Fetch fresh stats from D1
    const stats = await this.fetchStatsFromD1();

    // Update cache
    this.statsCache = stats;
    this.statsCacheTime = now;

    // Also store in durable storage for persistence across hibernation
    await this.ctx.storage.put('stats_cache', { stats, timestamp: now });

    return Response.json(stats);
  }

  private async fetchStatsFromD1(): Promise<ServerStats> {
    const db = this.env.DB;

    const [users, rooms, events, activeUsers, recentUsers, recentEvents, mediaStats, unresolvedReports] = await Promise.all([
      db.prepare('SELECT COUNT(*) as count FROM users').first<{ count: number }>(),
      db.prepare('SELECT COUNT(*) as count FROM rooms').first<{ count: number }>(),
      db.prepare('SELECT COUNT(*) as count FROM events').first<{ count: number }>(),
      db.prepare('SELECT COUNT(*) as count FROM users WHERE is_deactivated = 0').first<{ count: number }>(),
      db.prepare('SELECT COUNT(*) as count FROM users WHERE created_at > ?').bind(Date.now() - 86400000).first<{ count: number }>(),
      db.prepare('SELECT COUNT(*) as count FROM events WHERE origin_server_ts > ?').bind(Date.now() - 86400000).first<{ count: number }>(),
      db.prepare('SELECT COUNT(*) as count, COALESCE(SUM(content_length), 0) as total_size FROM media').first<{ count: number; total_size: number }>(),
      db.prepare('SELECT COUNT(*) as count FROM content_reports WHERE resolved = 0').first<{ count: number }>(),
    ]);

    return {
      users: {
        total: users?.count || 0,
        active: activeUsers?.count || 0,
        registrations_24h: recentUsers?.count || 0,
      },
      rooms: {
        total: rooms?.count || 0,
      },
      events: {
        total: events?.count || 0,
        last_24h: recentEvents?.count || 0,
      },
      media: {
        count: mediaStats?.count || 0,
        total_size_bytes: mediaStats?.total_size || 0,
      },
      unresolvedReports: unresolvedReports?.count || 0,
      lastUpdated: Date.now(),
    };
  }

  // Invalidate stats cache (called after admin actions that change data)
  private async handleInvalidateCache(): Promise<Response> {
    this.statsCache = null;
    this.statsCacheTime = 0;
    await this.ctx.storage.delete('stats_cache');
    return new Response('OK');
  }

  // WebSocket for real-time admin updates
  private async handleWebSocket(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected websocket upgrade', { status: 426 });
    }

    const url = new URL(request.url);
    const userId = url.searchParams.get('user_id');

    if (!userId) {
      return new Response('Missing user_id', { status: 400 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    this.ctx.acceptWebSocket(server, ['admin', userId]);

    const session: AdminSession = {
      userId,
      connectedAt: Date.now(),
    };
    server.serializeAttachment(session);

    // Send current stats immediately
    const stats = await this.fetchStatsFromD1();
    server.send(JSON.stringify({ type: 'stats', data: stats }));

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  // Broadcast message to all connected admin WebSockets
  private async handleBroadcast(request: Request): Promise<Response> {
    const message = await request.json();
    await this.broadcastToAdmins(message);
    return new Response('OK');
  }

  private async broadcastToAdmins(message: unknown): Promise<void> {
    const messageStr = JSON.stringify(message);
    const webSockets = this.ctx.getWebSockets('admin');

    for (const ws of webSockets) {
      try {
        ws.send(messageStr);
      } catch (e) {
        // WebSocket may be closed
      }
    }
  }

  // WebSocket message handler
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    try {
      const data = typeof message === 'string' ? JSON.parse(message) : null;
      if (!data) return;

      switch (data.type) {
        case 'ping':
          ws.send(JSON.stringify({ type: 'pong' }));
          break;

        case 'get_stats':
          const stats = await this.fetchStatsFromD1();
          ws.send(JSON.stringify({ type: 'stats', data: stats }));
          break;

        case 'get_config':
          const config = await this.getConfig();
          ws.send(JSON.stringify({ type: 'config', data: config }));
          break;

        default:
          break;
      }
    } catch (e) {
      console.error('Error handling admin WebSocket message:', e);
    }
  }

  async webSocketClose(_ws: WebSocket, _code: number, _reason: string, _wasClean: boolean): Promise<void> {
    // WebSocket is already closed, no action needed
  }

  async webSocketError(_ws: WebSocket, error: unknown): Promise<void> {
    console.error('Admin WebSocket error:', error);
  }

  // Alarm handler for periodic stats refresh
  async alarm(): Promise<void> {
    // Refresh stats cache
    this.statsCache = await this.fetchStatsFromD1();
    this.statsCacheTime = Date.now();
    await this.ctx.storage.put('stats_cache', { stats: this.statsCache, timestamp: this.statsCacheTime });

    // Broadcast updated stats to connected admins
    await this.broadcastToAdmins({ type: 'stats', data: this.statsCache });

    // Schedule next refresh in 1 minute
    await this.ctx.storage.setAlarm(Date.now() + 60000);
  }
}
