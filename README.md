# Matrix Homeserver on Cloudflare Workers

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wckd/matrix-workers)

This is a proof of concept Matrix homeserver implementation running entirely on Cloudflare's edge infrastructure. This was built to prove E2EE utilizing Matrix protocols over Element X on the Cloudflare Workers Platform. It is meant to serve as an example prototype and not endorsed as ready for production at this point.

> **Note:** This is a fork of [nkuntz1934/matrix-workers](https://github.com/nkuntz1934/matrix-workers) with extensive security and Matrix specification compliance improvements. See the [Security & Compliance](#security--compliance) section below for details on what we've added.

I was assisted by Claude Code Opus 4.5 for this implementation to speed up showing that you could message over Cloudflare Workers utilizing the Element Web and Element X App. Feel free to submit issues, fork the project to make it your own, or continue to build on this example!

## Live Demo

A live instance is running at `m.easydemo.org`. You can verify federation compatibility using the [Matrix Federation Tester](https://federationtester.matrix.org/#m.easydemo.org) or view the [full JSON report](https://federationtester.matrix.org/api/report?server_name=m.easydemo.org).

## Quick Start

### One-Click Deploy

The fastest way to deploy is using the Deploy to Cloudflare button at the top of this README. After clicking:

1. Cloudflare provisions all resources automatically
2. You need to update `SERVER_NAME` to your domain
3. Run database migrations
4. Configure your custom domain

**See [DEPLOYMENT.md](./DEPLOYMENT.md) for complete instructions.**

### Manual Deploy

```bash
# Clone and install
git clone https://github.com/wckd/matrix-workers
cd matrix-workers
npm install

# Create resources (save IDs from output)
npx wrangler d1 create my-matrix-db
npx wrangler kv namespace create SESSIONS
npx wrangler kv namespace create DEVICE_KEYS
npx wrangler kv namespace create ONE_TIME_KEYS
npx wrangler kv namespace create CROSS_SIGNING_KEYS
npx wrangler kv namespace create CACHE
npx wrangler kv namespace create ACCOUNT_DATA
npx wrangler r2 bucket create my-matrix-media

# Update wrangler.jsonc with your resource IDs and SERVER_NAME
# Then run migrations and deploy (see DEPLOYMENT.md for details)
```

**See [DEPLOYMENT.md](./DEPLOYMENT.md) for the complete step-by-step guide.**

### Email Verification (Optional)

For 3PID email verification support, configure [Resend](https://resend.com):

```bash
# Set your Resend API key
npx wrangler secret put RESEND_API_KEY

# Set the from email address (must match your verified domain)
npx wrangler secret put EMAIL_FROM
# Example: noreply@m.easydemo.org
```

> **Note:** Cloudflare's native [Email Workers](https://developers.cloudflare.com/email-routing/email-workers/send-email-workers/) currently only support sending to pre-verified destination addresses, making them unsuitable for verification emails to arbitrary users. Resend is used as a workaround until Cloudflare releases transactional email support for Workers.

## Spec Compliance

**[Matrix Specification v1.17](https://spec.matrix.org/v1.17/) Compliance**

| Spec Section | Implementation | Spec Reference |
|--------------|----------------|----------------|
| [Client-Server API](https://spec.matrix.org/v1.17/client-server-api/) | [`src/api/`](src/api/) | Auth, sync, rooms, messaging, profiles |
| [Server-Server API](https://spec.matrix.org/v1.17/server-server-api/) | [`src/api/federation.ts`](src/api/federation.ts) | Federation, PDUs, EDUs, key exchange |
| [Room Versions](https://spec.matrix.org/v1.17/rooms/) | [`src/services/events.ts`](src/services/events.ts) | v1-v12, event auth, state resolution |
| [End-to-End Encryption](https://spec.matrix.org/v1.17/client-server-api/#end-to-end-encryption) | [`src/api/keys.ts`](src/api/keys.ts), [`src/api/key-backups.ts`](src/api/key-backups.ts) | Device keys, OTKs, cross-signing, key backup |
| [OAuth 2.0 API](https://spec.matrix.org/v1.17/client-server-api/#oauth-20-api) | [`src/api/oauth.ts`](src/api/oauth.ts), [`src/api/oidc-auth.ts`](src/api/oidc-auth.ts) | MSC3861, MSC2965, MSC2967, MSC4191 |
| [Discovery](https://spec.matrix.org/v1.17/client-server-api/#server-discovery) | [`src/index.ts`](src/index.ts) | `.well-known/matrix/client`, `/versions` |
| [Content Repository](https://spec.matrix.org/v1.17/client-server-api/#content-repository) | [`src/api/media.ts`](src/api/media.ts) | Upload, download, thumbnails, MSC3916 |
| [Push Notifications](https://spec.matrix.org/v1.17/client-server-api/#push-notifications) | [`src/api/push.ts`](src/api/push.ts), [`src/workflows/`](src/workflows/) | Push rules, pushers |
| [Presence](https://spec.matrix.org/v1.17/client-server-api/#presence) | [`src/api/presence.ts`](src/api/presence.ts) | Online/offline status |
| [Typing Notifications](https://spec.matrix.org/v1.17/client-server-api/#typing-notifications) | [`src/api/typing.ts`](src/api/typing.ts) | Typing indicators |
| [Receipts](https://spec.matrix.org/v1.17/client-server-api/#receipts) | [`src/api/receipts.ts`](src/api/receipts.ts) | Read receipts |
| [Spaces](https://spec.matrix.org/v1.17/client-server-api/#spaces) | [`src/api/spaces.ts`](src/api/spaces.ts) | Space hierarchy |
| [VoIP](https://spec.matrix.org/v1.17/client-server-api/#voice-over-ip) | [`src/api/voip.ts`](src/api/voip.ts), [`src/api/calls.ts`](src/api/calls.ts) | TURN servers, MatrixRTC |
| [Account Data](https://spec.matrix.org/v1.17/client-server-api/#client-config) | [`src/api/account-data.ts`](src/api/account-data.ts) | User/room account data |
| [3PID Management](https://spec.matrix.org/v1.17/client-server-api/#adding-account-administrative-contact-information) | [`src/api/account.ts`](src/api/account.ts) | Email verification, 3PID binding |

**Unstable Features (MSCs)**

| Feature | Implementation | MSC |
|---------|----------------|-----|
| Sliding Sync | [`src/api/sliding-sync.ts`](src/api/sliding-sync.ts) | [MSC3575](https://github.com/matrix-org/matrix-spec-proposals/pull/3575), [MSC4186](https://github.com/matrix-org/matrix-spec-proposals/pull/4186) |
| Authenticated Media | [`src/api/media.ts`](src/api/media.ts) | [MSC3916](https://github.com/matrix-org/matrix-spec-proposals/pull/3916) |
| Cross-signing Reset | [`src/api/keys.ts`](src/api/keys.ts), [`src/api/oauth.ts`](src/api/oauth.ts) | [MSC4312](https://github.com/matrix-org/matrix-spec-proposals/pull/4312) |
| Account Management | [`src/api/oidc-auth.ts`](src/api/oidc-auth.ts) | [MSC4191](https://github.com/matrix-org/matrix-spec-proposals/pull/4191) |

## Security & Compliance

This fork implements comprehensive security and Matrix specification compliance features that were missing from the original implementation. All issues are tracked at [wckd/matrix-workers/issues](https://github.com/wckd/matrix-workers/issues).

### Completed Security Features

**Critical Priority - Federation Security**

These features protect against malicious federation servers and ensure cryptographic integrity:

- **#16: Ed25519 Cryptography** ([`src/utils/crypto.ts`](src/utils/crypto.ts)) - Implemented proper Ed25519 signature operations using Web Crypto API. The original implementation had broken placeholder code.
- **#1: PDU Signature Validation** ([`src/services/federation-keys.ts`](src/services/federation-keys.ts)) - Validates cryptographic signatures on all incoming federation events using `verifyServerSignature()`.
- **#2: Federation Authorization** ([`src/services/authorization.ts`](src/services/authorization.ts)) - Verifies that all incoming events are authorized according to Matrix auth rules (room version specific).
- **#3: Federation Request Signing** ([`src/services/federation-client.ts`](src/services/federation-client.ts)) - Signs all outgoing federation requests with server's Ed25519 key in X-Matrix header.
- **#8: Auth Chain Validation** ([`src/services/authorization.ts`](src/services/authorization.ts)) - Validates the `auth_events` chain on incoming PDUs to prevent authorization bypass.
- **#7: State Resolution v2** ([`src/services/state-resolution.ts`](src/services/state-resolution.ts)) - Implements the complete state resolution algorithm for handling conflicting state.
- **#6: Event Field Validation** ([`src/services/event-validation.ts`](src/services/event-validation.ts)) - Comprehensive validation for all event fields according to spec.

**High Priority - Security Hardening**

- **#4: Power Level Checks** ([`src/services/power-levels.ts`](src/services/power-levels.ts)) - Verifies users have sufficient power level for state events and actions.
- **#9: Redaction Content Stripping** ([`src/services/redaction.ts`](src/services/redaction.ts)) - Properly strips content from redacted events per Matrix specification.
- **#10: History Visibility Enforcement** ([`src/services/history-visibility.ts`](src/services/history-visibility.ts)) - Enforces `m.room.history_visibility` settings on `/messages`, `/context`, and `/sync` endpoints.
- **#11: Event Hashes Field** ([`src/utils/crypto.ts`](src/utils/crypto.ts)) - Adds required `hashes` field to events for federation compliance via `calculateContentHash()`.
- **#12: Rate Limiting** ([`src/durable-objects/RateLimitDurableObject.ts`](src/durable-objects/RateLimitDurableObject.ts)) - Rate limiting using Durable Objects (merged from [upstream](https://github.com/nkuntz1934/matrix-workers)).
- **#13: Restricted Room Joins** ([`src/services/authorization.ts`](src/services/authorization.ts)) - Enforces `join_rule: 'restricted'` with full `allow` list validation for space-based access control.
- **#14: User-Interactive Authentication** ([`src/services/uia.ts`](src/services/uia.ts)) - Complete UIA implementation with proper session tracking for sensitive operations.
- **#15: Sync State Section** ([`src/api/sync.ts`](src/api/sync.ts)) - Correct `state.events` population, `full_state` parameter, `timeline.limited`, and `prev_batch` handling.
- **#17: Membership Event Validation** ([`src/services/event-validation.ts`](src/services/event-validation.ts)) - Validates `third_party_invite` and `join_authorised_via_users_server` fields in membership events.

**Medium Priority**

- **#5: Room Alias Deletion Permissions** ([`src/api/aliases.ts`](src/api/aliases.ts)) - Enforces creator/admin permissions on room alias deletion.

### Implementation Details

**Signature Verification Architecture**

The implementation uses a unified signature verification system:

```typescript
// Main verification function - checks any server signature
verifyServerSignature(obj, server, db, cache, keyId?)

// Specialized wrappers
verifyPduSignature(pdu, origin, db, cache)      // For PDUs from federation
verifyRemoteSignature(obj, server, db, cache)   // For other signed objects
```

Federation keys are cached in both D1 and KV with TTL based on `valid_until_ts` from the remote server.

**Gradual Enforcement**

Security features support gradual rollout via the `SIGNATURE_ENFORCEMENT` environment variable:
- `'log'` - Log validation failures but allow events through (default for testing)
- `'enforce'` - Reject events that fail validation (production mode)

**Rate Limiting Architecture**

Rate limiting uses Durable Objects instead of KV to prevent cascading failures:
- Sliding window algorithm per-IP and per-user
- Survives Worker crashes
- Distributed across edge locations

### Testing

All security features have been tested against:
- matrix.org federation ([view test results](https://federationtester.matrix.org/api/report?server_name=m.easydemo.org))
- Element Web, Element X (iOS/Android)
- Manual federation attacks and edge cases

## Features

- **Full E2EE Support**: Device keys, cross-signing, key backup, one-time keys, federation key queries
- **Token Refresh**: Secure token rotation with single-use refresh tokens (KV-backed with auto-expiry)
- **Sliding Sync**: MSC3575 and MSC4186 (Simplified Sliding Sync for Element X)
- **Real-time**: Sync coordination via Durable Objects, presence with KV caching
- **Federation**: Complete server-to-server communication including E2EE, knock protocol, media, and directory
- **Media Storage**: R2-backed media with thumbnail generation and authenticated media (MSC3916)
- **Push Notifications**: APNs support (iOS direct push)
- **Video Calling**: MatrixRTC with LiveKit and Cloudflare Calls SFU integration
- **Knock Protocol**: Support for knock-to-join rooms via federation
- **Room Versions**: Full support for room versions 1-12
- **Admin Dashboard**: Full-featured web UI with charts, user management, keyboard shortcuts
- **Synapse API Compatibility**: Standard `/_synapse/admin/*` endpoints for tool compatibility

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Cloudflare Edge Network                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Workers   │  │  Durable    │  │     D1      │  │         R2          │ │
│  │   (Hono)    │──│  Objects    │──│  (SQLite)   │  │   (Object Storage)  │ │
│  │             │  │             │  │             │  │                     │ │
│  │ • Routing   │  │ • Room DO   │  │ • users     │  │ • Media files       │ │
│  │ • Auth      │  │ • Sync DO   │  │ • rooms     │  │ • Thumbnails        │ │
│  │ • API       │  │ • Fed DO    │  │ • events    │  │ • Avatars           │ │
│  │ • Rate Lim  │  │ • Keys DO   │  │ • keys      │  │                     │ │
│  └─────────────┘  │ • Push DO   │  │ • tokens    │  └─────────────────────┘ │
│         │         │ • Admin DO  │  └─────────────┘            │             │
│         │         │ • Call DO   │                             │             │
│         │         │ • Rate DO   │                             │             │
│         │         └─────────────┘         │                   │             │
│  ┌──────┴─────────────────────────────────┴───────────────────┴───────────┐ │
│  │                          KV Namespaces                                 │ │
│  │  SESSIONS · DEVICE_KEYS · CACHE · ONE_TIME_KEYS · CROSS_SIGNING_KEYS   │ │
│  │  ACCOUNT_DATA                                                          │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                     Workflows (Durable Execution)                      │ │
│  │  RoomJoinWorkflow · PushNotificationWorkflow                           │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## API Coverage

### Client-Server API

| Category | Endpoints | Status |
|----------|-----------|--------|
| Authentication | `/login`, `/register`, `/logout`, `/refresh`, `/auth_metadata`, `/login/get_token` | ✅ |
| Sync | `/sync`, Sliding Sync (MSC3575/MSC4186), filter persistence & application | ✅ |
| Rooms | Create, join, leave, invite, kick, ban, knock, upgrade, summary | ✅ |
| Messaging | Send, redact, edit, reply | ✅ |
| State | Room state, power levels | ✅ |
| E2EE | Device keys, OTKs, cross-signing, key backup | ✅ |
| To-Device | Encrypted message relay | ✅ |
| Push | Push rules, pushers (APNs/FCM) | ✅ |
| Media | Upload, download, thumbnails (MSC3916 auth) | ✅ |
| Profile | Display name, avatar, custom profile keys | ✅ |
| Presence | Online/offline status with KV caching | ✅ |
| Typing | Typing indicators | ✅ |
| Receipts | Read receipts | ✅ |
| Account Data | User settings, room tags | ✅ |
| Directory | Room directory, aliases | ✅ |
| Discovery | `.well-known/matrix/*` (client, server, support) | ✅ |
| Reporting | Report events, rooms, users | ✅ |
| Admin | User session info (`/admin/whois`), full admin API | ✅ |
| 3PID | Email verification, 3PID management | ✅ (Resend) |
| Timestamps | `timestamp_to_event` for event lookup | ✅ |

### Server-Server (Federation) API

| Category | Endpoint | Purpose | Status |
|----------|----------|---------|--------|
| **Discovery** | `GET /_matrix/federation/v1/version` | Server version info | ✅ |
| **Keys** | `GET /_matrix/key/v2/server` | Server signing keys | ✅ |
| | `GET /_matrix/key/v2/server/{keyId}` | Specific signing key | ✅ |
| | `POST /_matrix/key/v2/query` | Batch key query | ✅ |
| | `GET /_matrix/key/v2/query/{serverName}` | Notary key query | ✅ |
| | `GET /_matrix/key/v2/query/{serverName}/{keyId}` | Specific notary key | ✅ |
| **E2EE** | `POST /_matrix/federation/v1/user/keys/query` | Query device keys | ✅ |
| | `POST /_matrix/federation/v1/user/keys/claim` | Claim one-time keys | ✅ |
| | `GET /_matrix/federation/v1/user/devices/{userId}` | Get user devices | ✅ |
| **Events** | `PUT /_matrix/federation/v1/send/{txnId}` | Receive PDUs/EDUs | ✅ |
| | `GET /_matrix/federation/v1/event/{eventId}` | Fetch single event | ✅ |
| | `GET /_matrix/federation/v1/state/{roomId}` | Get room state | ✅ |
| | `GET /_matrix/federation/v1/state_ids/{roomId}` | Get state event IDs | ✅ |
| | `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}` | Get auth chain | ✅ |
| | `GET /_matrix/federation/v1/backfill/{roomId}` | Fetch historical events | ✅ |
| | `POST /_matrix/federation/v1/get_missing_events/{roomId}` | Fill event gaps | ✅ |
| | `GET /_matrix/federation/v1/timestamp_to_event/{roomId}` | Find event by timestamp | ✅ |
| **Joining** | `GET /_matrix/federation/v1/make_join/{roomId}/{userId}` | Prepare join | ✅ |
| | `PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}` | Complete join (v1) | ✅ |
| | `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}` | Complete join (v2) | ✅ |
| **Leaving** | `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}` | Prepare leave | ✅ |
| | `PUT /_matrix/federation/v1/send_leave/{roomId}/{eventId}` | Complete leave (v1) | ✅ |
| | `PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}` | Complete leave (v2) | ✅ |
| **Knocking** | `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}` | Prepare knock | ✅ |
| | `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}` | Complete knock | ✅ |
| **Inviting** | `PUT /_matrix/federation/v1/invite/{roomId}/{eventId}` | Receive invite (v1) | ✅ |
| | `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}` | Receive invite (v2) | ✅ |
| **Media** | `GET /_matrix/federation/v1/media/download/{mediaId}` | Download media | ✅ |
| | `GET /_matrix/federation/v1/media/thumbnail/{mediaId}` | Get thumbnail | ✅ |
| **Directory** | `GET /_matrix/federation/v1/query/directory` | Resolve room alias | ✅ |
| | `GET /_matrix/federation/v1/query/profile` | Query user profile | ✅ |
| | `GET /_matrix/federation/v1/publicRooms` | List public rooms | ✅ |
| | `POST /_matrix/federation/v1/publicRooms` | Search public rooms | ✅ |
| **Spaces** | `GET /_matrix/federation/v1/hierarchy/{roomId}` | Get space hierarchy | ✅ |
| **OpenID** | `GET /_matrix/federation/v1/openid/userinfo` | Validate OpenID token | ✅ |

### Matrix v1.17 Compliance Additions

The following endpoints were added to achieve full Matrix Specification v1.17 compliance:

| Category | Endpoint | Purpose |
|----------|----------|---------|
| **Room Summary** | `GET /_matrix/client/v1/room_summary/{roomIdOrAlias}` | Preview room without joining |
| **Auth Metadata** | `GET /_matrix/client/v1/auth_metadata` | Authentication method discovery |
| **Login Token** | `POST /_matrix/client/v1/login/get_token` | Generate short-lived login token (QR code login) |
| **Custom Profile** | `GET /_matrix/client/v3/profile/{userId}/{keyName}` | Get custom profile attribute |
| | `PUT /_matrix/client/v3/profile/{userId}/{keyName}` | Set custom profile attribute |
| | `DELETE /_matrix/client/v3/profile/{userId}/{keyName}` | Delete custom profile attribute |
| **Reporting** | `POST /_matrix/client/v3/rooms/{roomId}/report` | Report a room |
| | `POST /_matrix/client/v3/users/{userId}/report` | Report a user |
| **Admin** | `GET /_matrix/client/v3/admin/whois/{userId}` | Get user session/device info |
| **Timestamps** | `GET /_matrix/client/v3/rooms/{roomId}/timestamp_to_event` | Find event by timestamp |
| **3PID** | `POST /_matrix/client/v3/account/3pid/email/requestToken` | Request email verification |
| | `POST /_matrix/client/v3/account/3pid/submit_token` | Submit verification code |
| | `POST /_matrix/client/v3/account/3pid/add` | Add verified 3PID to account |
| **Federation** | `PUT /_matrix/federation/v1/exchange_third_party_invite/{roomId}` | Third-party invite exchange |
| **Sync Filters** | Filter loading and application | Filters are now applied during sync |

## Admin Dashboard

Access the admin dashboard at `/admin` on your server (e.g., `https://m.easydemo.org/admin`).

**Features:**
- **Dashboard** - Server stats, activity charts, user breakdown visualization
- **User Management** - Create, deactivate, purge users; reset passwords; bulk operations
- **Room Management** - View rooms, members, state; delete rooms; browse events
- **Media Management** - View uploads, quarantine/delete media
- **Reports** - Review and resolve content reports
- **Federation** - Monitor federation status with other servers
- **Identity Providers** - Configure OIDC/OAuth providers (Google, etc.)
- **Settings** - Toggle registration, send server notices

**Keyboard Shortcuts:**
- `Cmd/Ctrl+K` - Command palette
- `g h` - Go to Dashboard
- `g u` - Go to Users
- `g r` - Go to Rooms
- `/` - Focus search
- `?` - Show shortcuts help

**Synapse API Compatibility:**
Standard `/_synapse/admin/*` endpoints are available for compatibility with existing Matrix admin tools.

## Development

```bash
# Install dependencies
npm install

# Run locally
npm run dev

# Type check
npm run typecheck

# Run tests
npm run test

# Apply migrations locally
npm run db:migrate:local
```

## Testing

Unit tests for core Matrix functionality using Vitest:

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `event-validation.test.ts` | 25 | Matrix ID validation, event fields, PDU fields, state events |
| `redaction.test.ts` | 12 | Content stripping per event type, redacted event structure |
| `history-visibility.test.ts` | 17 | world_readable, shared, invited, joined visibility rules |
| `uia.test.ts` | 14 | UIA session completion, response building, standard flows |

**Total: 68 tests**

## Cloudflare Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `DB` | D1 | SQLite database for persistent data |
| `SESSIONS` | KV | Access tokens and refresh tokens (with TTL) |
| `DEVICE_KEYS` | KV | E2EE device keys |
| `ONE_TIME_KEYS` | KV | Olm prekeys |
| `CROSS_SIGNING_KEYS` | KV | Cross-signing keys |
| `CACHE` | KV | General caching (presence, federation txns, sync filters) |
| `ACCOUNT_DATA` | KV | User account data |
| `MEDIA` | R2 | Media file storage |
| `ROOMS` | Durable Object | Room coordination |
| `SYNC` | Durable Object | Sync state management |
| `FEDERATION` | Durable Object | Federation queue |
| `CALL_ROOMS` | Durable Object | Video call room coordination |
| `USER_KEYS` | Durable Object | E2EE key operations |
| `PUSH` | Durable Object | Push notification queue |
| `ADMIN` | Durable Object | Admin operations |
| `RATE_LIMIT` | Durable Object | Rate limiting |
| `ROOM_JOIN_WORKFLOW` | Workflow | Async room join processing |
| `PUSH_NOTIFICATION_WORKFLOW` | Workflow | Async push delivery |

## Security

This fork includes comprehensive security improvements over the original implementation. See the [Security & Compliance](#security--compliance) section above for complete details.

**Core Security Features:**
- **Password Hashing**: PBKDF2-SHA256 (100,000 iterations)
- **Token Format**: Secure random with user binding
- **Token Refresh**: Single-use refresh tokens with automatic rotation
- **Rate Limiting**: Sliding window per-IP and per-user via Durable Objects (from [upstream](https://github.com/nkuntz1934/matrix-workers))
- **Federation Auth**: Ed25519 request signing with X-Matrix header validation
- **PDU Validation**: Cryptographic signature verification on all incoming federation events
- **Authorization Checks**: Full Matrix auth rules enforcement (room version specific)
- **Event Validation**: Comprehensive field validation for all event types
- **History Visibility**: Enforced on all read endpoints
- **Power Levels**: Validated for all state changes
- **Media Auth**: Authenticated media endpoints (MSC3916)

## Compatibility

Tested with:
- Element Web
- Element X (iOS)
- Element X (Android)

Federation tested with:
- matrix.org ([view test results](https://federationtester.matrix.org/api/report?server_name=m.easydemo.org))

## Limitations

| Constraint | Limit | Notes |
|------------|-------|-------|
| Worker CPU | 30s | Use Workflows for long operations |
| Worker Memory | 128MB | Stream large responses |
| D1 Database | 10GB | Archive old events if needed |
| R2 Object | 5GB | Chunked upload supported |
| KV Value | 25MB | Split large datasets |

## License

MIT
