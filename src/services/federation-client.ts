// Federation HTTP Client
// Wrapper for fetch that adds Matrix request signing headers

import type { Env } from '../types/env';
import { signFederationRequest, signJson } from '../utils/crypto';

/**
 * Server signing key info
 */
interface ServerSigningKey {
  keyId: string;
  privateKey: string;
}

/**
 * Federation request options
 */
export interface FederationRequestOptions {
  method?: string;
  body?: Record<string, unknown>;
  timeout?: number;
}

/**
 * Federation response
 */
export interface FederationResponse<T = unknown> {
  ok: boolean;
  status: number;
  data?: T;
  error?: string;
}

const DEFAULT_TIMEOUT_MS = 30000; // 30 seconds

/**
 * Federation HTTP client with request signing
 */
export class FederationClient {
  private env: Env;
  private serverName: string;
  private signingKeyCache: ServerSigningKey | null = null;

  constructor(env: Env) {
    this.env = env;
    this.serverName = env.SERVER_NAME;
  }

  /**
   * Make a GET request to a federation endpoint
   */
  async get<T = unknown>(
    destination: string,
    path: string,
    options?: { timeout?: number }
  ): Promise<FederationResponse<T>> {
    return this.request<T>(destination, path, {
      method: 'GET',
      timeout: options?.timeout,
    });
  }

  /**
   * Make a PUT request to a federation endpoint
   */
  async put<T = unknown>(
    destination: string,
    path: string,
    body: Record<string, unknown>,
    options?: { timeout?: number }
  ): Promise<FederationResponse<T>> {
    return this.request<T>(destination, path, {
      method: 'PUT',
      body,
      timeout: options?.timeout,
    });
  }

  /**
   * Make a POST request to a federation endpoint
   */
  async post<T = unknown>(
    destination: string,
    path: string,
    body: Record<string, unknown>,
    options?: { timeout?: number }
  ): Promise<FederationResponse<T>> {
    return this.request<T>(destination, path, {
      method: 'POST',
      body,
      timeout: options?.timeout,
    });
  }

  /**
   * Make a signed federation request
   */
  async request<T = unknown>(
    destination: string,
    path: string,
    options: FederationRequestOptions = {}
  ): Promise<FederationResponse<T>> {
    const method = options.method || 'GET';
    const timeout = options.timeout || DEFAULT_TIMEOUT_MS;

    try {
      // Get signing key
      const signingKey = await this.getSigningKey();
      if (!signingKey) {
        return {
          ok: false,
          status: 500,
          error: 'No signing key available',
        };
      }

      // Build URL
      const url = `https://${destination}${path}`;

      // Sign the request
      const authHeader = await signFederationRequest(
        method,
        path,
        this.serverName,
        destination,
        signingKey.keyId,
        signingKey.privateKey,
        options.body
      );

      // Build headers
      const headers: Record<string, string> = {
        Authorization: authHeader,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      };

      // Create abort controller for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        const response = await fetch(url, {
          method,
          headers,
          body: options.body ? JSON.stringify(options.body) : undefined,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          let errorMessage = `HTTP ${response.status}`;
          try {
            const errorData = await response.json() as { error?: string; errcode?: string };
            errorMessage = errorData.error || errorData.errcode || errorMessage;
          } catch {
            // Ignore JSON parse errors
          }
          return {
            ok: false,
            status: response.status,
            error: errorMessage,
          };
        }

        const data = (await response.json()) as T;
        return {
          ok: true,
          status: response.status,
          data,
        };
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        return {
          ok: false,
          status: 0,
          error: 'Request timeout',
        };
      }
      return {
        ok: false,
        status: 0,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Sign a PDU/event for federation
   */
  async signEvent(event: Record<string, unknown>): Promise<Record<string, unknown>> {
    const signingKey = await this.getSigningKey();
    if (!signingKey) {
      throw new Error('No signing key available');
    }

    return signJson(event, this.serverName, signingKey.keyId, signingKey.privateKey);
  }

  /**
   * Get the server's signing key (cached)
   */
  private async getSigningKey(): Promise<ServerSigningKey | null> {
    if (this.signingKeyCache) {
      return this.signingKeyCache;
    }

    const key = await this.env.DB.prepare(
      `SELECT key_id, private_key FROM server_keys WHERE is_current = 1 LIMIT 1`
    ).first<{ key_id: string; private_key: string }>();

    if (!key) {
      console.error('No signing key found in database');
      return null;
    }

    this.signingKeyCache = {
      keyId: key.key_id,
      privateKey: key.private_key,
    };

    return this.signingKeyCache;
  }
}

/**
 * Create a federation client instance
 */
export function createFederationClient(env: Env): FederationClient {
  return new FederationClient(env);
}
