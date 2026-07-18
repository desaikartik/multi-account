# Managed Switcher — Backend

The admin-hosted **Backend-for-Frontend (BFF)** and sole trust boundary for the
Managed Claude Account Switcher. Holds all secrets and enforces every rule
server-side; the desktop client only ever holds a backend URL + per-user tokens.

> **Operating boundary (non-negotiable):** transparent, disclosed, visible tool.
> Nothing sensitive ships in the client; all secrets + enforcement are here.
> Server clock is authoritative (UTC everywhere). Tokens/PII never appear in API
> responses or logs.

> **Deploying?** See **`docs/admin/deployment-runbook.md`** for the full,
> ordered deploy steps (Render/Vercel, Atlas with two DB roles, secrets, geo,
> TLS), and **`docs/admin/onboarding.md`** for the legitimacy conditions.

## What Phase 1 delivers

Auth (signup + disposable/MX rejection, email OTP, login, token refresh with
rotation + reuse-detection, logout), live-read entitlements with an admin-only
mutation ledger, AES-256-GCM field encryption + HMAC blind index, a
tamper-evident HMAC hash-chained audit ledger with Ed25519 daily anchors and
`verify()`, request security (Host/Origin/Content-Type, per-route rate limits,
error hygiene), idempotent audit ingestion, and a seed/admin CLI.

**No client or dashboard UI in Phase 1.**

## Layout

```
backend/
  lib/            pure logic (config, repo, crypto, passwords, email, otp,
                  tokens, auth, entitlements, hashchain, audit, access, geo,
                  netip, retention, scheduler, presence, anomaly, commands,
                  devicecreds, reporting, transfer, watermark, webconsole,
                  httpsec, serverless, mailer, dns, admin, disposable-domains,
                  clock, errors)
  routes.js       method+path → handler map + transport-agnostic handleRequest()
  server.js       Node http server (adapts sockets → handleRequest)
  context.js      composition root (builds ctx for server.js + cli.js)
  mongoRepo.js    production repository (mongodb driver, cached client, indexes)
  cli.js          ops CLI (keygen, create-admin, verify-audit, verify-perms,
                  anchor, maintain)
  api/index.js    Vercel serverless entry (same handlers via lib/serverless.js)
  render.yaml     Render Blueprint (persistent web-service target)
  vercel.json     Vercel config (routes every path to api/index.js)
  public/         read-only admin web console (served by server.js only)
  *.test.js       node:test suites (run fully offline, zero installed deps)
```

Route handlers take a normalized request `{method,path,query,headers,body,ip}` +
an injected `ctx` and return `{status,body,headers}`, so the **same** handlers
run under `server.js` today and Vercel functions later. Data access is behind a
repository interface with a filter-object query language shared by the in-memory
repo (tests) and `mongoRepo.js` (production).

## Run the tests

```bash
cd backend
node --test        # full suite, no network, no installed dependencies
```

The suite uses the in-memory repo + an injected clock + a capture-fake mailer.
`mongodb` and `nodemailer` are lazy-required only by their real implementations
(`mongoRepo.js` / the Gmail mailer), which the suite never constructs. Ed25519
JWTs use Node's built-in `crypto` (no `jose`), so everything runs offline.

## Local demo (no DB, no Gmail)

```bash
cd backend
node cli.js keygen > .env        # generate key material (edit non-secret values)
REPO=memory MAILER=console node server.js
# → managed-switcher-backend listening on http://127.0.0.1:8787 (repo=memory)
```

`REPO=memory` uses the in-memory repo; `MAILER=console` prints OTP emails to the
terminal so you can complete signup → verify → login by hand. Example:

```bash
curl -s -H 'Host: 127.0.0.1' http://127.0.0.1:8787/health
curl -s -X POST -H 'Host: 127.0.0.1' -H 'Content-Type: application/json' \
  -d '{"email":"you@yourco.com","password":"password12345"}' \
  http://127.0.0.1:8787/auth/signup
# grab the 6-digit code from the server terminal, then:
curl -s -X POST -H 'Host: 127.0.0.1' -H 'Content-Type: application/json' \
  -d '{"email":"you@yourco.com","code":"123456"}' \
  http://127.0.0.1:8787/auth/verify-email
```

## Point it at real MongoDB Atlas

This is a summary; the full procedure (with exact least-privilege grants) is in
**`docs/admin/deployment-runbook.md` §2**.

1. Create an Atlas **M0** cluster on the `switcher` DB. TLS is on by default.
2. Create **two SCRAM database users** (least privilege):
   - **App role** (`MONGODB_URI`): insert + find; `deleteOne` on `ip_rules`
     only; updates on mutable collections; `createIndex`; `db.stats()`. It must
     **not** be able to delete from `audit_events` / `permission_changes`.
   - **Prune role** (`MONGODB_PRUNE_URI`): `deleteMany` on `audit_events` and
     `permission_changes` **only** — the single place ledger rows are ever
     deleted (the retention prune). See the "Audit retention & anchoring" note
     below and the role-split comment at the top of `mongoRepo.js`.
   - If you leave `MONGODB_PRUNE_URI` unset, the app falls back to one shared
     connection and the `MONGODB_URI` role must then also grant `deleteMany` on
     those two collections.
3. Atlas Network Access: because Render/Vercel free tiers have dynamic egress
   IPs, use `0.0.0.0/0` **with** the strong SCRAM credential + TLS as
   compensating controls. Upgrade path: a static-egress host → lock the
   allowlist to one IP.
4. Fill `backend/.env` (git-ignored):
   ```bash
   node cli.js keygen > .env     # then edit MONGODB_URI / GMAIL_* to real values
   ```
5. Seed the first admin, then run:
   ```bash
   node cli.js create-admin admin@yourco.com
   node server.js                # repo defaults to Mongo; HOST=0.0.0.0 for deploy
   ```

Required env (see `.env.example`): `MONGODB_URI`, `MONGODB_DB`, `FIELD_ENC_KEY`,
`BLIND_INDEX_KEY`, `AUDIT_HMAC_KEY`, `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY` (Ed25519),
`ANCHOR_PRIVATE_KEY`/`ANCHOR_PUBLIC_KEY` (Ed25519), `GMAIL_USER`,
`GMAIL_APP_PASSWORD`, `PORT`, `ALLOWED_HOSTS`. Deploy/topology + optional env:
`HOST`, `TRUST_PROXY`, `TRUSTED_PROXY_HOPS`, `SCHEDULER`, `RETENTION_DAYS`
(default 7), `MONGODB_PRUNE_URI`, `GEO_PROVIDER`/`GEO_API_URL`/`GEOLITE2_DB_PATH`,
`TLS_KEY_FILE`/`TLS_CERT_FILE`, `REPO`/`MAILER` (dev), and
`SEED_ADMIN_EMAIL`/`SEED_ADMIN_PASSWORD` (memory-repo demo only).

## API (current — 33 routes)

Full route map from `routes.js`'s `ROUTES`. `webView` marks the routes the
**read-only** admin web console is allowed to call (all are GETs). Everything
else the console cannot reach; every mutation and every credential read is
desktop-admin-only.

**Public (no auth) — 7**

| Method | Path                 | Purpose |
|--------|----------------------|---------|
| GET    | `/health`            | Liveness (platform health checks hit this — it still enforces the Host allowlist) |
| POST   | `/auth/signup`       | Create pending user + send OTP |
| POST   | `/auth/verify-email` | Confirm OTP → activate |
| POST   | `/auth/login`        | Password → access + refresh tokens |
| POST   | `/auth/web-login`    | Web-console login (view-scope token) |
| POST   | `/auth/refresh`      | Rotate tokens (reuse-detection) |
| POST   | `/auth/logout`       | Revoke session family |

**Bearer (any signed-in user) — 8**

| Method | Path                    | Purpose |
|--------|-------------------------|---------|
| GET    | `/entitlements/me`      | Live entitlement flags |
| POST   | `/audit/events`         | Idempotent audit ingestion |
| POST   | `/export/authorize`     | Authorize an account export (quota-gated) |
| POST   | `/import/authorize`     | Authorize an account import |
| POST   | `/heartbeat`            | Device check-in; also returns pending commands |
| POST   | `/commands/poll`        | Poll pending commands |
| POST   | `/commands/ack`         | Ack a command (at-least-once) |
| POST   | `/devices/claude-cred`  | Upload the D2 server-side encrypted credential backup |

**Bearer + admin — 18** (`✓` = also `webView`, i.e. read-only console can call it)

| Method | Path                                 | webView | Purpose |
|--------|--------------------------------------|:------:|---------|
| POST   | `/auth/change-password`              |        | Change password (admin-gated) |
| POST   | `/admin/entitlements`                |        | Grant/revoke flags (chained ledger) |
| GET    | `/admin/audit/verify`                | ✓      | Walk + verify the audit chain |
| POST   | `/admin/ip-rules`                    |        | Add an IP allow/block rule |
| POST   | `/admin/ip-rules/remove`             |        | Remove an IP rule |
| GET    | `/admin/ip-rules`                    | ✓      | List IP rules |
| POST   | `/admin/geo-fence`                   |        | Set a user's geo-fence |
| GET    | `/watermarks/trace`                  | ✓      | Trace a watermarked export |
| POST   | `/admin/commands`                    |        | Enqueue a remote command |
| POST   | `/admin/monitoring`                  |        | Toggle a device's monitoring |
| GET    | `/admin/reports/timeline`            | ✓      | Activity timeline report |
| GET    | `/admin/reports/devices`             | ✓      | Device list report |
| GET    | `/admin/reports/alerts`              | ✓      | Anomaly alerts report |
| GET    | `/admin/reports/storage`             | ✓      | Storage report (`db.stats()`) |
| GET    | `/admin/reports/transfers`           | ✓      | Export/import history report |
| GET    | `/admin/audit/export`                | ✓      | Signed audit export |
| GET    | `/admin/permission-changes/verify`   | ✓      | Verify the permission-change chain |
| GET    | `/admin/devices/claude-cred`         |        | Read the decrypted D2 credential backup (**deliberately NOT webView** — a decrypted credential must never reach a browser session) |

## CLI

```bash
node cli.js keygen                     # print a fresh .env with generated keys
node cli.js create-admin <email> [pw]  # create the first admin (prompts for pw)
node cli.js verify-audit               # verify the audit hash chain
node cli.js verify-perms               # verify the permission-change chain
node cli.js anchor                     # sign the current audit head
node cli.js maintain                   # one maintenance tick (anchor both chains,
                                       # verify, anchor-aligned prune); exit 2 on
                                       # chain-verify failure. Use as the external
                                       # cron on serverless (Vercel) targets.
```

## Audit retention & anchoring

Audit events are append-only and HMAC hash-chained; `cli.js anchor` signs the
current chain head with the Ed25519 anchor key. There is deliberately **no raw
time-based TTL** on `audit_events` — a time TTL prunes the chain at boundaries
unrelated to anchors and breaks seq-based verification. Retention is **7 days**
(`RETENTION_DAYS`, default 7) via an **anchor-aligned** prune: anchor the head,
then delete only events strictly below the newest anchor's `seqHigh`, so the
retained tail always starts exactly at an anchor checkpoint and `verify()` stays
sound.

The prune runs automatically on a persistent server via the in-process daily
scheduler (`SCHEDULER=on`, the default; keep it on for Render). On a serverless
(Vercel) target the in-process timer never fires, so run `node cli.js maintain`
from an **external** scheduler instead (see `render.yaml`/`api/index.js` comments
and the runbook). The prune is the only operation that deletes ledger rows, so in
production it should run under the separate delete-capable `MONGODB_PRUNE_URI`
role while the app runs insert+find-only under `MONGODB_URI`.

## Security notes (post-review hardening)

- Rate limiting keys on the socket peer IP; `X-Forwarded-For` is honored only
  when `TRUST_PROXY=true` (behind a known proxy).
- OTP attempt cap and refresh-token rotation use **atomic** conditional updates
  (no read-then-write races); refresh has a short grace window so a benign
  double-submit is a retry, not a family-wide logout.
- The two hash chains (`audit_events`, `permission_changes`) are domain-separated
  so rows cannot be transplanted between them.
- Login lockout, unknown-email, and wrong-password all return the same generic
  401 (no account-existence oracle).
- Audit ingestion accepts only client-originated event types and stamps
  identity from the token; idempotency keys are scoped per user.
- Unexpected 5xx error details are redacted before logging (no connection-string
  / secret leakage).
