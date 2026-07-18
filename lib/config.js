'use strict';
// Backend configuration loader + key material.
//
// Security invariants:
//  - Secrets live ONLY in the backend environment (never in the client).
//  - loadConfig() validates presence + shape and reports MISSING VAR NAMES
//    only — it never echoes a secret value into an error message or log.
//  - Ed25519 keys are parsed into Node crypto KeyObjects up front so callers
//    never handle raw PEM at signing time.

const crypto = require('crypto');

const KEY_BYTES = 32; // AES-256 + HMAC-SHA256 keys are all 32 raw bytes.

// Parse a base64 secret into a Buffer, asserting an exact byte length.
function parseKeyBytes(name, value, errors) {
  if (!value) { errors.push(`Missing ${name}`); return null; }
  let buf;
  try {
    buf = Buffer.from(String(value), 'base64');
  } catch {
    errors.push(`${name} is not valid base64`);
    return null;
  }
  if (buf.length !== KEY_BYTES) {
    errors.push(`${name} must be ${KEY_BYTES} bytes (base64) — got ${buf.length}`);
    return null;
  }
  return buf;
}

// PEM may arrive with literal "\n" escapes (single-line .env). Normalize them.
function normalizePem(value) {
  return String(value).includes('\\n') ? String(value).replace(/\\n/g, '\n') : String(value);
}

function parsePrivateKey(name, value, errors) {
  if (!value) { errors.push(`Missing ${name}`); return null; }
  try {
    const key = crypto.createPrivateKey(normalizePem(value));
    if (key.asymmetricKeyType !== 'ed25519') {
      errors.push(`${name} must be an Ed25519 private key`);
      return null;
    }
    return key;
  } catch {
    errors.push(`${name} is not a valid private key`);
    return null;
  }
}

function parsePublicKey(name, value, errors) {
  if (!value) { errors.push(`Missing ${name}`); return null; }
  try {
    const key = crypto.createPublicKey(normalizePem(value));
    if (key.asymmetricKeyType !== 'ed25519') {
      errors.push(`${name} must be an Ed25519 public key`);
      return null;
    }
    return key;
  } catch {
    errors.push(`${name} is not a valid public key`);
    return null;
  }
}

function loadConfig(env = process.env) {
  const errors = [];

  const fieldEncKey = parseKeyBytes('FIELD_ENC_KEY', env.FIELD_ENC_KEY, errors);
  const blindIndexKey = parseKeyBytes('BLIND_INDEX_KEY', env.BLIND_INDEX_KEY, errors);
  const auditHmacKey = parseKeyBytes('AUDIT_HMAC_KEY', env.AUDIT_HMAC_KEY, errors);

  const jwtPrivateKey = parsePrivateKey('JWT_PRIVATE_KEY', env.JWT_PRIVATE_KEY, errors);
  const jwtPublicKey = parsePublicKey('JWT_PUBLIC_KEY', env.JWT_PUBLIC_KEY, errors);
  const anchorPrivateKey = parsePrivateKey('ANCHOR_PRIVATE_KEY', env.ANCHOR_PRIVATE_KEY, errors);
  const anchorPublicKey = parsePublicKey('ANCHOR_PUBLIC_KEY', env.ANCHOR_PUBLIC_KEY, errors);

  if (!env.MONGODB_URI) errors.push('Missing MONGODB_URI');

  // Optional in-process TLS (Phase 6): both-or-neither. When neither is set the
  // server stays plain HTTP (byte-identical to today); when both are set,
  // server.js builds an https.createServer from these file paths.
  const tlsKeyFile = env.TLS_KEY_FILE || null;
  const tlsCertFile = env.TLS_CERT_FILE || null;
  if (tlsKeyFile && !tlsCertFile) errors.push('Missing TLS_CERT_FILE (TLS_KEY_FILE is set)');
  if (tlsCertFile && !tlsKeyFile) errors.push('Missing TLS_KEY_FILE (TLS_CERT_FILE is set)');

  if (errors.length) {
    // NOTE: only variable NAMES appear here — never their (secret) values.
    throw new Error('Invalid backend configuration: ' + errors.join('; '));
  }

  const port = Number(env.PORT || 8787);
  const allowedHosts = String(env.ALLOWED_HOSTS || '127.0.0.1,localhost')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  // Only trust X-Forwarded-For when explicitly behind a known proxy. Otherwise
  // a client could spoof the header and defeat per-IP rate limits.
  const trustProxy = String(env.TRUST_PROXY || '').toLowerCase() === 'true';
  // Number of trusted proxies that APPEND to X-Forwarded-For between the client
  // and this backend. The real client IP is xff[len - trustedProxyHops]. This
  // MUST exactly equal the appending-proxy count; if the XFF is shorter than
  // this (spoof/misconfig) resolveClientIp fails CLOSED to the socket peer,
  // never to the client-controlled leftmost entry.
  const trustedProxyHops = Math.max(1, Number(env.TRUSTED_PROXY_HOPS || 1) || 1);

  // Geo/IP provider wiring (Phase 6): which real geo resolver to wire up in
  // context.js. 'none' (default) keeps today's fail-closed behavior (any
  // geo-fenced user is locked out until a provider is configured).
  const geoProvider = String(env.GEO_PROVIDER || 'none').toLowerCase();
  const geoApiUrl = env.GEO_API_URL || 'http://ip-api.com/json';
  const geolite2DbPath = env.GEOLITE2_DB_PATH || null;

  return {
    fieldEncKey,
    blindIndexKey,
    auditHmacKey,
    jwtPrivateKey,
    jwtPublicKey,
    anchorPrivateKey,
    anchorPublicKey,
    mongoUri: env.MONGODB_URI,
    mongoDb: env.MONGODB_DB || 'switcher',
    // Phase 6 Task 3 — role split: a SEPARATE delete-capable Mongo connection
    // string for the retention prune (the only delete on the append-only
    // audit_events/permission_changes ledgers). Optional (not validated as
    // required — unlike MONGODB_URI above): when unset, ctx.pruneRepo is never
    // built (context.js) and runMaintenance falls back to the single shared
    // app connection (today's behavior, unchanged). When set, this MUST point
    // at an Atlas/Mongo role granted deleteMany on those two collections ONLY
    // — the app's own role (MONGODB_URI) should stay insert+find(+the few
    // mutable-collection ops listed in mongoRepo.js) and never gain delete on
    // the ledgers.
    mongoPruneUri: env.MONGODB_PRUNE_URI || null,
    gmailUser: env.GMAIL_USER,
    gmailAppPassword: env.GMAIL_APP_PASSWORD,
    port,
    allowedHosts,
    trustProxy,
    trustedProxyHops,
    tlsKeyFile,
    tlsCertFile,
    geoProvider,
    geoApiUrl,
    geolite2DbPath,
    // Task 13 (D2 upload kill-switch) — INFORMATIONAL ECHO ONLY. The DESKTOP CLIENT is
    // the actual enforcer: src/core/config.js's `devicecredUploadEnabled` decides
    // whether main.js's sealAndUpload() ever calls POST /devices/claude-cred at all.
    // This backend field has NO server-side gating effect on that route (it stays
    // reachable regardless) — it exists only so ops/config-dump tooling can see the
    // fleet-wide intended setting alongside the client-side app-config.json value.
    devicecredUploadEnabled: String(env.DEVICECRED_UPLOAD_ENABLED || 'true').toLowerCase() !== 'false',
    // Dev-only admin seed for REPO=memory live verification (Phase 5 Task 3).
    // Inert everywhere else — context.js only invokes the seed when the
    // in-memory repo is selected, regardless of whether these are set.
    seedAdminEmail: env.SEED_ADMIN_EMAIL || null,
    seedAdminPassword: env.SEED_ADMIN_PASSWORD || null,
    // Tunables (documented defaults; overridable later).
    scrypt: { N: 1 << 15, r: 8, p: 1, keylen: 32 },
    otp: {
      ttlMs: 5 * 60 * 1000,       // 5-minute validity
      maxAttempts: 5,             // wrong-guess cap per code
      length: 6,
      maxSendsPerWindow: 5,       // send rate limit per user+purpose
      rateWindowMs: 15 * 60 * 1000,
    },
    accessTokenTtlMs: 15 * 60 * 1000,
    refreshTokenTtlMs: 60 * 24 * 60 * 60 * 1000,
    // Grace window after a refresh token is rotated during which re-presenting
    // it (with its live replacement still valid) is treated as a benign
    // double-submit (retry) rather than theft. Bounds the reuse-detection race.
    refreshGraceMs: 10 * 1000,
    // Absolute cap on a refresh-token FAMILY regardless of rotation. Sliding
    // rotation renews the token indefinitely; this bounds total session life so
    // a long-lived stolen family cannot outlive re-authentication forever (#11).
    refreshAbsoluteLifetimeMs: 90 * 24 * 60 * 60 * 1000,
    loginLockout: { maxFails: 5, windowMs: 15 * 60 * 1000, cooldownMs: 15 * 60 * 1000 },
    // Phase 2 control-plane tunables.
    retentionDays: Number(env.RETENTION_DAYS || 7), // Addendum B: 7-day anchor-aligned prune (NOT a raw TTL).
    anchorIntervalMs: 24 * 60 * 60 * 1000,          // scheduler: anchor both chains daily
    pruneIntervalMs: 24 * 60 * 60 * 1000,           // scheduler: anchor-aligned prune daily
    anomaly: {
      impossibleTravelKmh: 900,               // faster than this between two fixes ⇒ impossible travel
      impossibleTravelWindowMs: 24 * 60 * 60 * 1000,
      minTravelMinutes: 5,                    // ignore fixes closer than this in time (kills ÷~0)
      minTravelKm: 100,                       // ignore tiny hops (coarse-geo jitter, multi-device at one site)
      repeatedFailWindowMs: 15 * 60 * 1000,
      repeatedFailThreshold: 10,              // per-IP failed logins in the window ⇒ warn
      deadManDays: 7,                         // device holding creds silent longer ⇒ warn
      newDeviceIsAnomaly: true,
    },
  };
}

// Generate a complete fresh set of key material as env-ready strings.
// Used by the seed CLI (`node cli.js keygen`) and by the test suite.
function generateKeys() {
  const jwt = crypto.generateKeyPairSync('ed25519');
  const anchor = crypto.generateKeyPairSync('ed25519');
  const pem = { private: { type: 'pkcs8', format: 'pem' }, public: { type: 'spki', format: 'pem' } };
  return {
    FIELD_ENC_KEY: crypto.randomBytes(KEY_BYTES).toString('base64'),
    BLIND_INDEX_KEY: crypto.randomBytes(KEY_BYTES).toString('base64'),
    AUDIT_HMAC_KEY: crypto.randomBytes(KEY_BYTES).toString('base64'),
    JWT_PRIVATE_KEY: jwt.privateKey.export(pem.private),
    JWT_PUBLIC_KEY: jwt.publicKey.export(pem.public),
    ANCHOR_PRIVATE_KEY: anchor.privateKey.export(pem.private),
    ANCHOR_PUBLIC_KEY: anchor.publicKey.export(pem.public),
  };
}

// Load KEY=VALUE pairs from a .env file into an object (no external dep).
// Supports quoted values and `#` comments. Does not mutate process.env.
function parseEnvFile(text) {
  const out = {};
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

// Render a ready-to-paste .env with FRESH key material. Non-secret values fall
// back to the current env (or illustrative placeholders). PEM newlines are
// escaped to \n so each var is a single line.
function buildEnvTemplate(env = {}) {
  const keys = generateKeys();
  const esc = pem => pem.replace(/\n/g, '\\n');
  const lines = [
    '# Managed Switcher backend .env — generated by `node cli.js keygen`.',
    '# Keep secret. This file is git-ignored. Never commit real values.',
    '',
    `MONGODB_URI=${env.MONGODB_URI || 'mongodb+srv://USER:PASSWORD@cluster0.example.mongodb.net/?retryWrites=true&w=majority'}`,
    `MONGODB_DB=${env.MONGODB_DB || 'switcher'}`,
    `FIELD_ENC_KEY=${keys.FIELD_ENC_KEY}`,
    `BLIND_INDEX_KEY=${keys.BLIND_INDEX_KEY}`,
    `AUDIT_HMAC_KEY=${keys.AUDIT_HMAC_KEY}`,
    `JWT_PRIVATE_KEY="${esc(keys.JWT_PRIVATE_KEY)}"`,
    `JWT_PUBLIC_KEY="${esc(keys.JWT_PUBLIC_KEY)}"`,
    `ANCHOR_PRIVATE_KEY="${esc(keys.ANCHOR_PRIVATE_KEY)}"`,
    `ANCHOR_PUBLIC_KEY="${esc(keys.ANCHOR_PUBLIC_KEY)}"`,
    `GMAIL_USER=${env.GMAIL_USER || 'you@example.com'}`,
    `GMAIL_APP_PASSWORD=${env.GMAIL_APP_PASSWORD || 'xxxx xxxx xxxx xxxx'}`,
    `PORT=${env.PORT || '8787'}`,
    `ALLOWED_HOSTS=${env.ALLOWED_HOSTS || '127.0.0.1,localhost'}`,
    '',
  ];
  return { keys, text: lines.join('\n') };
}

module.exports = { loadConfig, generateKeys, parseEnvFile, buildEnvTemplate, KEY_BYTES };
