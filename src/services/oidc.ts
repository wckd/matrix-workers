// OIDC (OpenID Connect) service for IdP integration
// Handles discovery, token exchange, and JWT validation

export interface OIDCDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
}

export interface OIDCTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token: string;
  scope?: string;
}

export interface OIDCUserClaims {
  sub: string;                    // Subject - unique user ID from IdP
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
}

export interface JWK {
  kty: string;
  use?: string;
  kid?: string;
  alg?: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
  crv?: string;
}

export interface JWKS {
  keys: JWK[];
}

// Cache for OIDC discovery documents and JWKS
const discoveryCache = new Map<string, { data: OIDCDiscovery; expiresAt: number }>();
const jwksCache = new Map<string, { data: JWKS; expiresAt: number }>();

const CACHE_TTL = 3600000; // 1 hour

/**
 * Fetch OIDC discovery document from issuer
 */
export async function fetchOIDCDiscovery(issuerUrl: string): Promise<OIDCDiscovery> {
  // Normalize issuer URL
  const normalizedIssuer = issuerUrl.replace(/\/$/, '');

  // Check cache
  const cached = discoveryCache.get(normalizedIssuer);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.data;
  }

  const discoveryUrl = `${normalizedIssuer}/.well-known/openid-configuration`;

  const response = await fetch(discoveryUrl, {
    headers: { 'Accept': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch OIDC discovery from ${discoveryUrl}: ${response.status}`);
  }

  const discovery = await response.json() as OIDCDiscovery;

  // Validate required fields
  if (!discovery.issuer || !discovery.authorization_endpoint || !discovery.token_endpoint || !discovery.jwks_uri) {
    throw new Error('Invalid OIDC discovery document: missing required fields');
  }

  // Cache the result
  discoveryCache.set(normalizedIssuer, {
    data: discovery,
    expiresAt: Date.now() + CACHE_TTL,
  });

  return discovery;
}

/**
 * Fetch JWKS (JSON Web Key Set) from IdP
 */
export async function fetchJWKS(jwksUri: string): Promise<JWKS> {
  // Check cache
  const cached = jwksCache.get(jwksUri);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.data;
  }

  const response = await fetch(jwksUri, {
    headers: { 'Accept': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS from ${jwksUri}: ${response.status}`);
  }

  const jwks = await response.json() as JWKS;

  // Cache the result
  jwksCache.set(jwksUri, {
    data: jwks,
    expiresAt: Date.now() + CACHE_TTL,
  });

  return jwks;
}

/**
 * Build the authorization URL for the OAuth flow
 */
export function buildAuthorizationUrl(
  discovery: OIDCDiscovery,
  clientId: string,
  redirectUri: string,
  scopes: string,
  state: string,
  nonce: string
): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes,
    state: state,
    nonce: nonce,
  });

  return `${discovery.authorization_endpoint}?${params.toString()}`;
}

/**
 * Exchange authorization code for tokens
 */
export async function exchangeCodeForTokens(
  discovery: OIDCDiscovery,
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string
): Promise<OIDCTokenResponse> {
  const response = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
    }).toString(),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Token exchange failed: ${response.status} - ${error}`);
  }

  return await response.json() as OIDCTokenResponse;
}

/**
 * Decode a JWT without verification (for reading header/payload)
 */
export function decodeJWT(token: string): { header: any; payload: any; signature: string } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
  const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

  return { header, payload, signature: parts[2] };
}

/**
 * Import a JWK as a CryptoKey for verification
 */
async function importJWK(jwk: JWK): Promise<CryptoKey> {
  const algorithm = jwk.alg || 'RS256';

  // Web Crypto API algorithm parameters
  let importAlgorithm: any;

  if (algorithm.startsWith('RS') || algorithm.startsWith('PS')) {
    importAlgorithm = {
      name: algorithm.startsWith('PS') ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
      hash: { name: `SHA-${algorithm.slice(-3)}` },
    };
  } else if (algorithm.startsWith('ES')) {
    const curves: Record<string, string> = {
      'ES256': 'P-256',
      'ES384': 'P-384',
      'ES512': 'P-521',
    };
    importAlgorithm = {
      name: 'ECDSA',
      namedCurve: curves[algorithm] || 'P-256',
    };
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  return await crypto.subtle.importKey(
    'jwk',
    jwk as JsonWebKey,
    importAlgorithm,
    false,
    ['verify']
  );
}

/**
 * Verify JWT signature using JWKS
 */
async function verifyJWTSignature(token: string, jwks: JWKS): Promise<boolean> {
  const { header, signature } = decodeJWT(token);
  const parts = token.split('.');
  const signedData = `${parts[0]}.${parts[1]}`;

  // Find the matching key
  let key: JWK | undefined;
  if (header.kid) {
    key = jwks.keys.find(k => k.kid === header.kid);
  }
  if (!key) {
    // Try first key with matching algorithm
    key = jwks.keys.find(k => k.alg === header.alg || !k.alg);
  }
  if (!key) {
    throw new Error('No matching key found in JWKS');
  }

  const cryptoKey = await importJWK({ ...key, alg: header.alg });

  // Decode signature from base64url
  const signatureBytes = Uint8Array.from(
    atob(signature.replace(/-/g, '+').replace(/_/g, '/')),
    c => c.charCodeAt(0)
  );

  const algorithm = header.alg;
  let verifyAlgorithm: any;

  if (algorithm.startsWith('RS')) {
    verifyAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
  } else if (algorithm.startsWith('PS')) {
    verifyAlgorithm = {
      name: 'RSA-PSS',
      saltLength: parseInt(algorithm.slice(-3)) / 8,
    };
  } else if (algorithm.startsWith('ES')) {
    verifyAlgorithm = {
      name: 'ECDSA',
      hash: { name: `SHA-${algorithm.slice(-3)}` },
    };
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  return await crypto.subtle.verify(
    verifyAlgorithm,
    cryptoKey,
    signatureBytes,
    new TextEncoder().encode(signedData)
  );
}

/**
 * Validate an ID token and extract claims
 */
export async function validateIDToken(
  idToken: string,
  issuerUrl: string,
  clientId: string,
  nonce: string,
  jwks: JWKS
): Promise<OIDCUserClaims> {
  const { payload } = decodeJWT(idToken);

  // Verify signature
  const signatureValid = await verifyJWTSignature(idToken, jwks);
  if (!signatureValid) {
    throw new Error('Invalid ID token signature');
  }

  // Validate issuer
  const normalizedIssuer = issuerUrl.replace(/\/$/, '');
  if (payload.iss !== normalizedIssuer && payload.iss !== `${normalizedIssuer}/`) {
    throw new Error(`Invalid issuer: expected ${normalizedIssuer}, got ${payload.iss}`);
  }

  // Validate audience
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(clientId)) {
    throw new Error(`Invalid audience: ${payload.aud}`);
  }

  // Validate expiration
  if (payload.exp && payload.exp < Date.now() / 1000) {
    throw new Error('ID token has expired');
  }

  // Validate nonce
  if (payload.nonce !== nonce) {
    throw new Error('Invalid nonce');
  }

  // Validate issued at (allow 5 minute clock skew)
  if (payload.iat && payload.iat > Date.now() / 1000 + 300) {
    throw new Error('ID token issued in the future');
  }

  return {
    sub: payload.sub,
    email: payload.email,
    email_verified: payload.email_verified,
    name: payload.name,
    preferred_username: payload.preferred_username,
    picture: payload.picture,
    given_name: payload.given_name,
    family_name: payload.family_name,
  };
}

/**
 * Generate a cryptographically secure random string for state/nonce
 */
export function generateRandomString(length: number = 32): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Derive a Matrix username from OIDC claims
 */
export function deriveUsername(claims: OIDCUserClaims, usernameClaim: string): string {
  let username: string;

  switch (usernameClaim) {
    case 'email':
      if (!claims.email) {
        throw new Error('Email claim not available');
      }
      // Use the part before @ as username
      username = claims.email.split('@')[0];
      break;
    case 'preferred_username':
      if (!claims.preferred_username) {
        throw new Error('preferred_username claim not available');
      }
      username = claims.preferred_username;
      break;
    case 'sub':
      username = claims.sub;
      break;
    default:
      throw new Error(`Unknown username claim: ${usernameClaim}`);
  }

  // Sanitize username for Matrix (lowercase, allowed chars only)
  username = username.toLowerCase().replace(/[^a-z0-9._=-]/g, '_');

  // Ensure it's not empty
  if (!username) {
    username = `user_${claims.sub.substring(0, 8)}`;
  }

  return username;
}
