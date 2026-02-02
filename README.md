# Matrix Homeserver on Cloudflare Workers

A proof-of-concept Matrix homeserver running entirely on Cloudflare's edge infrastructure with full E2EE support.

> **Fork Note:** This is a fork of [nkuntz1934/matrix-workers](https://github.com/nkuntz1934/matrix-workers) with security improvements and Matrix spec compliance fixes.

## Quick Links

- [Live Demo](https://m.easydemo.org) | [Federation Test](https://federationtester.matrix.org/#m.easydemo.org)
- [Matrix Spec v1.17](https://spec.matrix.org/v1.17/)

## Deployment

### Prerequisites

- Cloudflare account with **Workers Paid plan** ($5/month) - required for Durable Objects
- Node.js 18+
- A domain managed by Cloudflare

### Step 1: Clone and Install

```bash
git clone https://github.com/wckd/matrix-workers
cd matrix-workers
npm install
npx wrangler login
```

### Step 2: Create Cloudflare Resources

Run these commands and **save all the IDs** from the output:

```bash
# Get your account ID
npx wrangler whoami

# Create D1 database
npx wrangler d1 create matrix-db

# Create KV namespaces
npx wrangler kv namespace create SESSIONS
npx wrangler kv namespace create DEVICE_KEYS
npx wrangler kv namespace create CACHE
npx wrangler kv namespace create CROSS_SIGNING_KEYS
npx wrangler kv namespace create ACCOUNT_DATA
npx wrangler kv namespace create ONE_TIME_KEYS

# Create R2 bucket
npx wrangler r2 bucket create matrix-media
```

### Step 3: Configure wrangler.jsonc

Open `wrangler.jsonc` and update these values:

```jsonc
{
  "name": "my-matrix-server",                    // Your worker name
  "account_id": "YOUR_ACCOUNT_ID",               // From wrangler whoami

  "d1_databases": [{
    "binding": "DB",
    "database_name": "matrix-db",                // Name you chose
    "database_id": "YOUR_DATABASE_ID"            // From d1 create output
  }],

  "kv_namespaces": [
    { "binding": "SESSIONS", "id": "YOUR_ID" },
    { "binding": "DEVICE_KEYS", "id": "YOUR_ID" },
    { "binding": "CACHE", "id": "YOUR_ID" },
    { "binding": "CROSS_SIGNING_KEYS", "id": "YOUR_ID" },
    { "binding": "ACCOUNT_DATA", "id": "YOUR_ID" },
    { "binding": "ONE_TIME_KEYS", "id": "YOUR_ID" }
  ],

  "r2_buckets": [{
    "binding": "MEDIA",
    "bucket_name": "matrix-media"                // Name you chose
  }],

  "vars": {
    "SERVER_NAME": "matrix.yourdomain.com"       // Your Matrix domain (cannot change later!)
  },

  "routes": [{
    "pattern": "matrix.yourdomain.com",          // Must match SERVER_NAME
    "custom_domain": true
  }]
}
```

#### Optional: Remove LiveKit VPC (if not using video calls)

If you don't have a LiveKit server, **remove or comment out** the `vpc_services` section:

```jsonc
// Remove this entire section if you don't have a VPC service configured:
"vpc_services": [
  {
    "binding": "LIVEKIT_API",
    "service_id": "..."
  }
]
```

Also remove the LiveKit vars if not using:
```jsonc
"vars": {
  "SERVER_NAME": "...",
  // Remove these:
  // "LIVEKIT_API_KEY": "...",
  // "LIVEKIT_URL": "..."
}
```

### Step 4: Run Database Migrations

Apply all migrations in order:

```bash
DB_NAME="matrix-db"  # Your database name

npx wrangler d1 execute $DB_NAME --remote --file=migrations/schema.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/002_phase1_e2ee.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/003_account_management.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/004_reports_and_notices.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/005_server_config.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/005_idp_providers.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/006_query_optimization.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/007_secure_server_keys.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/008_federation_transactions.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/009_reports_extended.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/010_fix_reports_schema.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/011_identity_service.sql
npx wrangler d1 execute $DB_NAME --remote --file=migrations/012_redaction_tracking.sql
```

### Step 5: Deploy

```bash
npx wrangler deploy
```

### Step 6: Verify

```bash
# Test endpoints
curl https://matrix.yourdomain.com/_matrix/client/versions
curl https://matrix.yourdomain.com/_matrix/federation/v1/version

# Register first user
curl -X POST "https://matrix.yourdomain.com/_matrix/client/v3/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secure-password","auth":{"type":"m.login.dummy"}}'
```

Run the [Federation Tester](https://federationtester.matrix.org) with your server name.

## Optional Features

### Email Verification (3PID)

```bash
npx wrangler secret put RESEND_API_KEY   # From resend.com
npx wrangler secret put EMAIL_FROM       # e.g., noreply@yourdomain.com
```

### TURN Server (Voice/Video)

```bash
# Add to wrangler.jsonc vars:
# "TURN_KEY_ID": "your-turn-key-id"

npx wrangler secret put TURN_API_TOKEN
```

### APNs Push (iOS)

```bash
npx wrangler secret put APNS_KEY_ID       # From Apple Developer Portal
npx wrangler secret put APNS_TEAM_ID      # Your Team ID
npx wrangler secret put APNS_PRIVATE_KEY  # Contents of .p8 file
```

### LiveKit (MatrixRTC Video)

Requires a LiveKit server and Cloudflare VPC service configured:

```bash
# Add to wrangler.jsonc vars:
# "LIVEKIT_API_KEY": "your-key"
# "LIVEKIT_URL": "wss://your-livekit.com"

npx wrangler secret put LIVEKIT_API_SECRET
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Cloudflare Edge Network                       │
├─────────────────────────────────────────────────────────────────┤
│  Workers (Hono)     D1 (SQLite)      KV Namespaces     R2       │
│  ├─ API routing     ├─ users         ├─ SESSIONS       Media    │
│  ├─ Auth            ├─ rooms         ├─ DEVICE_KEYS    storage  │
│  └─ Rate limiting   ├─ events        ├─ CACHE                   │
│                     └─ keys          └─ ...                     │
├─────────────────────────────────────────────────────────────────┤
│  Durable Objects                    Workflows                   │
│  ├─ Room coordination               ├─ RoomJoinWorkflow         │
│  ├─ Sync state                      └─ PushNotificationWorkflow │
│  ├─ Federation queue                                            │
│  ├─ User keys                                                   │
│  ├─ Push notifications                                          │
│  └─ Rate limiting                                               │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Full E2EE**: Device keys, cross-signing, key backup, OTKs
- **Sliding Sync**: MSC3575/MSC4186 for Element X
- **Federation**: Complete server-to-server API with signature validation
- **Media**: R2 storage with thumbnails, authenticated media (MSC3916)
- **Push**: APNs support for iOS
- **Video Calls**: MatrixRTC with LiveKit/Cloudflare Calls
- **Admin Dashboard**: Web UI at `/admin`
- **Room Versions**: 1-12 supported

## Client Compatibility

Tested with:
- Element Web
- Element X (iOS/Android)

## API Coverage

### Client-Server API

| Category | Status |
|----------|--------|
| Auth (login, register, logout, refresh) | ✅ |
| Sync (including Sliding Sync) | ✅ |
| Rooms (create, join, leave, invite, knock) | ✅ |
| Messaging (send, redact, edit) | ✅ |
| E2EE (device keys, OTKs, cross-signing, backup) | ✅ |
| Push (rules, pushers) | ✅ |
| Media (upload, download, thumbnails) | ✅ |
| Presence, Typing, Receipts | ✅ |
| Account Data, Directory | ✅ |
| 3PID (email verification) | ✅ |

### Server-Server API

| Category | Status |
|----------|--------|
| Server keys and discovery | ✅ |
| E2EE key query/claim | ✅ |
| PDU/EDU send | ✅ |
| Room join/leave/knock/invite | ✅ |
| State and backfill | ✅ |
| Media federation | ✅ |
| Directory and profile queries | ✅ |

## Security

This fork implements comprehensive security features:

- **Ed25519 signatures** on all federation requests
- **PDU signature validation** on incoming events
- **Authorization checks** per Matrix auth rules
- **State resolution v2** for conflict handling
- **Rate limiting** via Durable Objects (from [upstream](https://github.com/nkuntz1934/matrix-workers))
- **History visibility** enforcement
- **Power level** validation
- **Redaction** content stripping per spec

See [GitHub Issues](https://github.com/wckd/matrix-workers/issues) for implementation tracking.

## Development

```bash
npm install          # Install dependencies
npm run dev          # Local development
npm run test         # Run tests (68 tests)
npm run typecheck    # TypeScript check
npm run deploy       # Deploy to Cloudflare
```

## Troubleshooting

### "Workers Paid plan required"

Durable Objects require Workers Paid ($5/month).

### "target ... not found" (VPC error)

Remove or comment out the `vpc_services` section in `wrangler.jsonc` if you don't have a VPC service.

### "Authentication error"

The `account_id` in `wrangler.jsonc` doesn't match your logged-in account. Update it with your account ID from `npx wrangler whoami`.

### Federation test fails

1. Ensure domain DNS is managed by Cloudflare
2. Check `.well-known/matrix/server` returns correctly
3. Verify signing keys are generated (happens on first request)

### View logs

```bash
npx wrangler tail
```

## Limitations

| Resource | Limit |
|----------|-------|
| Worker CPU | 30s |
| Worker Memory | 128MB |
| D1 Database | 10GB |
| R2 Object | 5GB |
| KV Value | 25MB |

## License

MIT
