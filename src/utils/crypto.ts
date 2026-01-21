// Cryptographic utilities for Matrix homeserver

// Hash a password using PBKDF2 (Web Crypto compatible alternative to Argon2)
export async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hash = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  // Format: $pbkdf2-sha256$iterations$salt$hash
  const saltB64 = btoa(String.fromCharCode(...salt));
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
  return `$pbkdf2-sha256$100000$${saltB64}$${hashB64}`;
}

// Verify a password against a hash
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split('$');
  if (parts.length !== 5 || parts[1] !== 'pbkdf2-sha256') {
    return false;
  }

  const iterations = parseInt(parts[2], 10);
  const salt = Uint8Array.from(atob(parts[3]), c => c.charCodeAt(0));
  const expectedHash = parts[4];

  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hash = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
  return hashB64 === expectedHash;
}

// SHA-256 hash
export async function sha256(data: string | Uint8Array): Promise<string> {
  const encoder = new TextEncoder();
  const bytes = typeof data === 'string' ? encoder.encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Hash an access token for storage
export async function hashToken(token: string): Promise<string> {
  return sha256(token);
}

// Generate Ed25519 key pair for signing
export async function generateSigningKeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
  keyId: string;
}> {
  // Ed25519 is not directly supported in Web Crypto, use a seed-based approach
  // For production, consider using a library like tweetnacl
  const seed = crypto.getRandomValues(new Uint8Array(32));

  // Generate a key ID
  const keyIdBytes = crypto.getRandomValues(new Uint8Array(4));
  const keyId = `ed25519:${Array.from(keyIdBytes).map(b => b.toString(16).padStart(2, '0')).join('')}`;

  // For now, store the seed as both public and private (placeholder)
  // In production, use proper Ed25519 implementation
  const publicKey = btoa(String.fromCharCode(...seed.slice(0, 32)));
  const privateKey = btoa(String.fromCharCode(...seed));

  return { publicKey, privateKey, keyId };
}

// Sign a JSON object (placeholder - needs proper Ed25519)
export async function signJson(
  obj: Record<string, unknown>,
  serverName: string,
  keyId: string,
  _privateKey: string
): Promise<Record<string, unknown>> {
  // Canonical JSON representation
  const canonical = canonicalJson(obj);
  const hash = await sha256(canonical);

  // Placeholder signature - in production use Ed25519
  const signature = hash;

  return {
    ...obj,
    signatures: {
      [serverName]: {
        [keyId]: signature,
      },
    },
  };
}

// Canonical JSON for signing
export function canonicalJson(obj: unknown): string {
  if (obj === null || obj === undefined) {
    return 'null';
  }

  if (typeof obj === 'boolean' || typeof obj === 'number') {
    return JSON.stringify(obj);
  }

  if (typeof obj === 'string') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    const items = obj.map(item => canonicalJson(item));
    return `[${items.join(',')}]`;
  }

  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(key => {
      const value = canonicalJson((obj as Record<string, unknown>)[key]);
      return `${JSON.stringify(key)}:${value}`;
    });
    return `{${pairs.join(',')}}`;
  }

  return 'null';
}

// Calculate content hash for PDU
export async function calculateContentHash(content: Record<string, unknown>): Promise<string> {
  // Remove signatures and unsigned before hashing
  const toHash = { ...content };
  delete toHash['signatures'];
  delete toHash['unsigned'];

  const canonical = canonicalJson(toHash);
  return sha256(canonical);
}

// Verify content hash
export async function verifyContentHash(
  content: Record<string, unknown>,
  expectedHash: string
): Promise<boolean> {
  const actualHash = await calculateContentHash(content);
  return actualHash === expectedHash;
}

// Generate a random string for CSRF tokens, etc.
export function generateRandomString(length: number = 32): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}
