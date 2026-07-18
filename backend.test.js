'use strict';
// Managed Switcher backend — Phase 1 test suite (node:test).
//
// Runs fully offline with ZERO installed dependencies: everything uses the
// in-memory repository, an injected deterministic clock, and a capture-fake
// mailer. mongodb/nodemailer are only lazy-required by the real
// implementations (mongoRepo.js / mailer.js), which the suite never constructs.
//
// Run:  cd backend && node --test

const { test } = require('node:test');
const assert = require('node:assert');

const { makeClock } = require('./lib/clock');
const { generateKeys, loadConfig } = require('./lib/config');
const { createMemoryRepo } = require('./lib/repo');
const { createFieldCrypto } = require('./lib/crypto');
const { hashPassword, verifyPassword } = require('./lib/passwords');
const { normalizeEmail, isValidEmail } = require('./lib/email');
const users = require('./lib/users');
const { isDisposableDomain } = require('./lib/disposable-domains');
const signup = require('./lib/signup');
const otp = require('./lib/otp');
const { createCaptureMailer } = require('./lib/mailer');
const tokens = require('./lib/tokens');
const auth = require('./lib/auth');
const hashchain = require('./lib/hashchain');
const entitlements = require('./lib/entitlements');
const audit = require('./lib/audit');
const { resolveClientIp } = require('./lib/httpsec');
const routes = require('./routes');
const admin = require('./lib/admin');
const { buildEnvTemplate, parseEnvFile } = require('./lib/config');
const netip = require('./lib/netip');
const geo = require('./lib/geo');
const devicecreds = require('./lib/devicecreds');
const usagestore = require('./lib/usagestore');

// A geo resolver double returning a fixed record for every IP (tests override
// with specific country/lat/lon as needed).
function fakeGeo(record) {
  return { async lookup() { return record; } };
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// A complete, valid env built from freshly generated key material, so tests
// exercise real crypto without touching the network or the filesystem.
function fullEnv(overrides = {}) {
  return {
    ...generateKeys(),
    MONGODB_URI: 'mongodb+srv://u:p@localhost/?tls=true',
    MONGODB_DB: 'switcher_test',
    GMAIL_USER: 'ops@example.com',
    GMAIL_APP_PASSWORD: 'aaaa bbbb cccc dddd',
    PORT: '8787',
    ...overrides,
  };
}

// Assemble a full backend context (ctx) wired to the in-memory repo, a fixed
// clock, real field-crypto, and generated keys. This is the dependency bundle
// every service function receives — the seam that makes the whole backend
// testable offline.
function makeCtx(overrides = {}) {
  const config = loadConfig(fullEnv());
  const clock = makeClock(1_700_000_000_000); // fixed, plausible UTC epoch (2023-11-14)
  const repo = createMemoryRepo();
  const crypto = createFieldCrypto(config.fieldEncKey, config.blindIndexKey);
  // Injected DNS: by default every domain resolves to an MX record. Individual
  // tests override resolveMx to simulate no-MX / DNS-failure domains.
  const resolveMx = async () => [{ exchange: 'mx.test', priority: 10 }];
  const resolveHost = async () => []; // no A/AAAA fallback unless a test overrides
  const mailer = createCaptureMailer();
  const logger = { info() {}, error() {} };
  const geoResolver = geo.createNullGeoResolver(); // default: no geo; tests override with fakeGeo(...)
  return { config, clock, repo, crypto, resolveMx, resolveHost, mailer, logger, geo: geoResolver, ...overrides };
}

// Build a normalized request object (as the HTTP adapter would hand to
// handleRequest). Header keys are lowercased, mirroring Node's http server.
function req(method, path, opts = {}) {
  const headers = { host: '127.0.0.1', ...(opts.headers || {}) };
  if (method !== 'GET' && headers['content-type'] === undefined && !('content-type' in (opts.headers || {}))) {
    headers['content-type'] = 'application/json';
  }
  return { method, path, query: opts.query || {}, headers, body: opts.body, ip: opts.ip || '1.2.3.4' };
}

// Sign in and return an "Authorization: Bearer <token>" header value.
async function bearerFor(ctx, email, password, deviceId = 'dev-1') {
  const res = await auth.login(ctx, { email, password, deviceId });
  return 'Bearer ' + res.accessToken;
}

// Return a VIEW-SCOPE bearer for an existing admin. /auth/web-login now mints a
// FULL admin session (the product uses a full-admin web console), so to keep
// exercising the still-present view-scope gate we mint a scope:'view' access
// token DIRECTLY here rather than through web-login. The admin account must
// already exist (the caller creates it). `password` is unused now but kept so
// this stays a drop-in for the existing call sites.
async function webBearerFor(ctx, email, password, deviceId = 'web-dev-1') { // eslint-disable-line no-unused-vars
  const user = await users.findUserByEmail(ctx, email);
  if (!user) throw new Error(`webBearerFor: no user ${email}`);
  const token = tokens.signAccessToken(ctx, { userId: user._id, role: user.role, deviceId, scope: 'view' });
  return 'Bearer ' + token;
}

// Extract the 6-digit code from the most recently "sent" email (capture mailer).
function lastOtpCode(ctx) {
  const msg = ctx.mailer.sent[ctx.mailer.sent.length - 1];
  const m = /\b(\d{6})\b/.exec(msg ? msg.text : '');
  return m ? m[1] : null;
}

// Create an already-active, email-verified user with a known password.
async function makeActiveUser(ctx, { email, password, role = 'member' } = {}) {
  const u = await users.createUser(ctx, { email, password, role });
  await ctx.repo.users.updateById(u._id, { status: 'active', emailVerified: true });
  return ctx.repo.users.findById(u._id);
}

// ===========================================================================
// STEP 1 — clock, config loader, in-memory repository
// ===========================================================================

test('clock: injected clock is deterministic and advanceable', () => {
  const clock = makeClock(1_000);
  assert.equal(clock.nowMs(), 1_000);
  assert.ok(clock.now() instanceof Date);
  assert.equal(clock.now().getTime(), 1_000);
  clock.advance(5_000);
  assert.equal(clock.nowMs(), 6_000);
  assert.equal(clock.now().getTime(), 6_000);
});

test('config: generateKeys + loadConfig round-trips into usable key material', () => {
  const cfg = loadConfig(fullEnv());
  assert.ok(Buffer.isBuffer(cfg.fieldEncKey) && cfg.fieldEncKey.length === 32);
  assert.ok(Buffer.isBuffer(cfg.blindIndexKey) && cfg.blindIndexKey.length === 32);
  assert.ok(Buffer.isBuffer(cfg.auditHmacKey) && cfg.auditHmacKey.length === 32);
  // Ed25519 KeyObjects, ready for crypto.sign/verify.
  assert.equal(cfg.jwtPrivateKey.asymmetricKeyType, 'ed25519');
  assert.equal(cfg.jwtPublicKey.asymmetricKeyType, 'ed25519');
  assert.equal(cfg.anchorPrivateKey.asymmetricKeyType, 'ed25519');
  assert.equal(cfg.anchorPublicKey.asymmetricKeyType, 'ed25519');
  assert.equal(cfg.mongoDb, 'switcher_test');
  assert.equal(cfg.port, 8787);
});

test('config: missing vars throw listing NAMES but never secret VALUES', () => {
  const secret = generateKeys().FIELD_ENC_KEY; // a real base64 secret value
  let err;
  try {
    loadConfig({ FIELD_ENC_KEY: secret }); // everything else missing
  } catch (e) {
    err = e;
  }
  assert.ok(err, 'expected loadConfig to throw on incomplete env');
  // Names of the missing vars are reported...
  assert.match(err.message, /BLIND_INDEX_KEY/);
  assert.match(err.message, /AUDIT_HMAC_KEY/);
  assert.match(err.message, /JWT_PRIVATE_KEY/);
  // ...but the one secret value we DID provide must never be echoed.
  assert.ok(!err.message.includes(secret), 'error message leaked a secret value');
});

test('config: rejects a FIELD_ENC_KEY that is not 32 bytes', () => {
  const short = Buffer.alloc(16).toString('base64');
  assert.throws(
    () => loadConfig(fullEnv({ FIELD_ENC_KEY: short })),
    /FIELD_ENC_KEY/,
  );
});

test('repo: generic collection insert / findById / updateById round-trip', async () => {
  const repo = createMemoryRepo();
  const doc = await repo.users.insert({ email: 'a@b.c', status: 'pending', createdAt: new Date(1) });
  assert.ok(doc._id, 'insert assigns an _id');
  const found = await repo.users.findById(doc._id);
  assert.equal(found.email, 'a@b.c');
  // Stored copies are isolated from caller mutation.
  found.email = 'mutated';
  const again = await repo.users.findById(doc._id);
  assert.equal(again.email, 'a@b.c', 'stored doc must be cloned, not aliased');

  await repo.users.updateById(doc._id, { status: 'active' });
  const updated = await repo.users.findById(doc._id);
  assert.equal(updated.status, 'active');
  assert.equal(updated.email, 'a@b.c', 'update is a partial patch');
});

test('repo: preserves Date and Buffer types across store/retrieve', async () => {
  const repo = createMemoryRepo();
  const d = new Date(1234567);
  const b = Buffer.from([1, 2, 3, 4]);
  const doc = await repo.users.insert({ createdAt: d, blob: b });
  const found = await repo.users.findById(doc._id);
  assert.ok(found.createdAt instanceof Date && found.createdAt.getTime() === 1234567);
  assert.ok(Buffer.isBuffer(found.blob) && found.blob.equals(b));
});

test('repo: audit collection is append-only (no update/delete surface)', async () => {
  const repo = createMemoryRepo();
  assert.equal(typeof repo.auditEvents.insert, 'function');
  assert.equal(typeof repo.auditEvents.getHead, 'function');
  assert.equal(typeof repo.auditEvents.find, 'function');
  // The tamper-evidence guarantee: the repo exposes NO mutation surface.
  assert.equal(repo.auditEvents.updateById, undefined);
  assert.equal(repo.auditEvents.deleteById, undefined);
  assert.equal(repo.auditEvents.updateOne, undefined);
  assert.equal(repo.auditEvents.deleteOne, undefined);
});

test('repo: audit seq is unique — duplicate insert is rejected', async () => {
  const repo = createMemoryRepo();
  assert.equal(await repo.auditEvents.getHead(), null);
  await repo.auditEvents.insert({ seq: 1, entryHash: 'h1', prevHash: 'GENESIS' });
  const head = await repo.auditEvents.getHead();
  assert.equal(head.seq, 1);
  await assert.rejects(
    () => repo.auditEvents.insert({ seq: 1, entryHash: 'dup', prevHash: 'h1' }),
    /duplicate|seq/i,
    'inserting an existing seq must be rejected to protect the chain',
  );
});

// ===========================================================================
// STEP 2 — field-crypto primitive, scrypt passwords, email normalize, users
// ===========================================================================

test('crypto: field encryption round-trips and uses a fresh IV each time', () => {
  const c = createFieldCrypto(Buffer.alloc(32, 7), Buffer.alloc(32, 9));
  const a = c.encrypt('alice@example.com');
  const b = c.encrypt('alice@example.com');
  assert.notEqual(a, b, 'same plaintext must produce different ciphertext (random IV)');
  assert.equal(c.decrypt(a), 'alice@example.com');
  assert.equal(c.decrypt(b), 'alice@example.com');
});

test('crypto: tampering with ciphertext makes decrypt throw (GCM auth)', () => {
  const c = createFieldCrypto(Buffer.alloc(32, 7), Buffer.alloc(32, 9));
  const enc = c.encrypt('secret');
  const raw = Buffer.from(enc, 'base64');
  raw[raw.length - 1] ^= 0xff; // flip a ciphertext byte
  assert.throws(() => c.decrypt(raw.toString('base64')));
});

test('crypto: blind index is deterministic and key-dependent', () => {
  const c1 = createFieldCrypto(Buffer.alloc(32, 1), Buffer.alloc(32, 2));
  const c2 = createFieldCrypto(Buffer.alloc(32, 1), Buffer.alloc(32, 3)); // different index key
  assert.equal(c1.blindIndex('a@b.com'), c1.blindIndex('a@b.com'));
  assert.notEqual(c1.blindIndex('a@b.com'), c1.blindIndex('c@d.com'));
  assert.notEqual(c1.blindIndex('a@b.com'), c2.blindIndex('a@b.com'), 'index must depend on the key');
});

test('crypto: constructor rejects non-32-byte keys', () => {
  assert.throws(() => createFieldCrypto(Buffer.alloc(16), Buffer.alloc(32)));
  assert.throws(() => createFieldCrypto(Buffer.alloc(32), Buffer.alloc(31)));
});

test('passwords: scrypt hash/verify round-trip; wrong password fails', () => {
  const params = { N: 1 << 14, r: 8, p: 1, keylen: 32 }; // lighter for test speed
  const enc = hashPassword('correct horse battery staple', params);
  assert.match(enc, /^scrypt\$/);
  assert.equal(verifyPassword('correct horse battery staple', enc), true);
  assert.equal(verifyPassword('wrong password', enc), false);
});

test('passwords: same password hashes differently (random salt) but both verify', () => {
  const params = { N: 1 << 14, r: 8, p: 1, keylen: 32 };
  const a = hashPassword('hunter2hunter2', params);
  const b = hashPassword('hunter2hunter2', params);
  assert.notEqual(a, b);
  assert.equal(verifyPassword('hunter2hunter2', a), true);
  assert.equal(verifyPassword('hunter2hunter2', b), true);
});

test('passwords: verify never throws on malformed input', () => {
  assert.equal(verifyPassword('x', ''), false);
  assert.equal(verifyPassword('x', 'not-a-hash'), false);
  assert.equal(verifyPassword('x', 'scrypt$abc'), false);
  assert.equal(verifyPassword('x', null), false);
});

test('email: normalize trims + lowercases and is idempotent', () => {
  assert.equal(normalizeEmail('  Alice@Example.COM '), 'alice@example.com');
  assert.equal(normalizeEmail(normalizeEmail(' Bob@X.io ')), 'bob@x.io');
});

test('email: isValidEmail accepts sane addresses, rejects junk', () => {
  assert.equal(isValidEmail('a@b.co'), true);
  assert.equal(isValidEmail('first.last@sub.domain.io'), true);
  assert.equal(isValidEmail('no-at-sign'), false);
  assert.equal(isValidEmail('a@b'), false);
  assert.equal(isValidEmail('a b@c.com'), false);
  assert.equal(isValidEmail(''), false);
});

test('users: createUser stores an encrypted + blind-indexed pending user, no plaintext PII/secret', async () => {
  const ctx = makeCtx();
  const user = await users.createUser(ctx, { email: '  Alice@Example.com ', password: 'password12345' });
  assert.equal(user.status, 'pending');
  assert.equal(user.emailVerified, false);
  assert.equal(user.importEnabled, false);
  assert.equal(user.exportEnabled, false);
  assert.equal(user.role, 'member');
  // No plaintext email, no plaintext password anywhere on the record.
  const blob = JSON.stringify(user);
  assert.ok(!blob.includes('Alice@Example.com') && !blob.toLowerCase().includes('alice@example.com'));
  assert.ok(!blob.includes('password12345'));
  assert.match(user.passwordHash, /^scrypt\$/);
  assert.ok(user.emailIdx && user.emailEnc);
  // The stored email decrypts back to the normalized address (via decryptEmail,
  // which supplies the record-binding AAD).
  assert.equal(users.decryptEmail(ctx, user), 'alice@example.com');
});

test('users/fix #21: emailEnc is AAD-bound to _id — cannot be relocated to another user record', async () => {
  const ctx = makeCtx();
  const a = await users.createUser(ctx, { email: 'alice@superworks.com', password: 'password12345' });
  const b = await users.createUser(ctx, { email: 'bob@superworks.com', password: 'password12345' });
  // Decrypts correctly against its own record.
  assert.equal(users.decryptEmail(ctx, a), 'alice@superworks.com');
  // A DB-write attacker who copies alice's emailEnc onto bob's record is caught:
  // decrypting bob (AAD='email:'+bob._id) against alice's ciphertext fails auth.
  const forged = { ...b, emailEnc: a.emailEnc };
  assert.throws(() => users.decryptEmail(ctx, forged), 'relocated ciphertext must fail GCM auth');
});

test('users: findUserByEmail matches case-insensitively via blind index', async () => {
  const ctx = makeCtx();
  await users.createUser(ctx, { email: 'Carol@Example.com', password: 'password12345' });
  const found = await users.findUserByEmail(ctx, '  carol@example.COM ');
  assert.ok(found, 'should find regardless of case/whitespace');
  assert.equal(users.decryptEmail(ctx, found), 'carol@example.com');
});

test('users: duplicate email is rejected (409)', async () => {
  const ctx = makeCtx();
  await users.createUser(ctx, { email: 'dup@example.com', password: 'password12345' });
  await assert.rejects(
    () => users.createUser(ctx, { email: 'DUP@example.com', password: 'password12345' }),
    (e) => e.status === 409,
  );
});

test('users: weak password and invalid email are rejected (400)', async () => {
  const ctx = makeCtx();
  await assert.rejects(() => users.createUser(ctx, { email: 'x@y.com', password: 'short' }), (e) => e.status === 400);
  await assert.rejects(() => users.createUser(ctx, { email: 'nope', password: 'password12345' }), (e) => e.status === 400);
});

// ===========================================================================
// STEP 3 — signup: disposable-domain blocklist + MX check, pending user
// ===========================================================================

test('disposable: blocks known disposable domains and their subdomains', () => {
  assert.equal(isDisposableDomain('mailinator.com'), true);
  assert.equal(isDisposableDomain('inbox.mailinator.com'), true); // subdomain
  assert.equal(isDisposableDomain('guerrillamail.com'), true);
  assert.equal(isDisposableDomain('10minutemail.com'), true);
  assert.equal(isDisposableDomain('MAILINATOR.COM'), true); // case-insensitive
});

test('disposable: allows normal + corporate domains', () => {
  assert.equal(isDisposableDomain('gmail.com'), false);
  assert.equal(isDisposableDomain('superworks.com'), false);
  assert.equal(isDisposableDomain('acme.co.uk'), false);
});

test('signup: valid work email creates a pending user, response has no PII/secret', async () => {
  const ctx = makeCtx();
  const res = await signup.signup(ctx, { email: 'New.User@superworks.com', password: 'password12345' });
  assert.equal(res.status, 'pending');
  assert.equal(res.emailVerified, false);
  assert.ok(res.userId);
  const blob = JSON.stringify(res);
  assert.ok(!blob.toLowerCase().includes('new.user@superworks.com'));
  assert.ok(!blob.includes('password12345'));
  assert.ok(!/scrypt\$/.test(blob), 'must not leak password hash');
  // The user really exists and is pending with gates OFF.
  const stored = await users.findUserByEmail(ctx, 'new.user@superworks.com');
  assert.equal(stored.status, 'pending');
  assert.equal(stored.importEnabled, false);
  assert.equal(stored.exportEnabled, false);
});

test('signup: rejects disposable email domain (422)', async () => {
  const ctx = makeCtx();
  await assert.rejects(
    () => signup.signup(ctx, { email: 'throwaway@mailinator.com', password: 'password12345' }),
    (e) => e.status === 422,
  );
  // and no user was created
  assert.equal(await users.findUserByEmail(ctx, 'throwaway@mailinator.com'), null);
});

test('signup: rejects a domain with no MX records (422)', async () => {
  const ctx = makeCtx({ resolveMx: async () => [] });
  await assert.rejects(
    () => signup.signup(ctx, { email: 'user@no-mail-domain.example', password: 'password12345' }),
    (e) => e.status === 422,
  );
});

test('signup: rejects when the MX lookup fails/throws (fail closed, 422)', async () => {
  const ctx = makeCtx({
    resolveMx: async () => { const e = new Error('queryMx ENOTFOUND'); e.code = 'ENOTFOUND'; throw e; },
  });
  await assert.rejects(
    () => signup.signup(ctx, { email: 'user@does-not-resolve.example', password: 'password12345' }),
    (e) => e.status === 422,
  );
});

test('signup: rejects invalid email before doing any DNS lookup (400)', async () => {
  let dnsCalled = false;
  const ctx = makeCtx({ resolveMx: async () => { dnsCalled = true; return []; } });
  await assert.rejects(() => signup.signup(ctx, { email: 'not-an-email', password: 'password12345' }), (e) => e.status === 400);
  assert.equal(dnsCalled, false, 'must not hit DNS for a syntactically invalid email');
});

test('signup: duplicate email is rejected (409)', async () => {
  const ctx = makeCtx();
  await signup.signup(ctx, { email: 'dup@superworks.com', password: 'password12345' });
  await assert.rejects(
    () => signup.signup(ctx, { email: 'DUP@superworks.com', password: 'password12345' }),
    (e) => e.status === 409,
  );
});

// ===========================================================================
// STEP 4 — email OTP: generate, send (captured), verify, TTL, attempt cap, RL
// ===========================================================================

test('otp: generateCode returns a zero-padded 6-digit numeric string', () => {
  for (let i = 0; i < 200; i++) {
    const code = otp.generateCode(6);
    assert.match(code, /^\d{6}$/);
  }
});

test('signup: creates a PENDING account and sends NO code (OTP removed — admin approval activates it)', async () => {
  const ctx = makeCtx();
  const res = await signup.signup(ctx, { email: 'otp@superworks.com', password: 'password12345' });
  assert.equal(res.status, 'pending');
  assert.equal(res.pendingApproval, true);
  assert.equal(ctx.mailer.sent.length, 0, 'no OTP email is sent anymore');
  assert.equal((await ctx.repo.otps.find({})).length, 0, 'no OTP is issued anymore');
  const user = await users.findUserByEmail(ctx, 'otp@superworks.com');
  assert.equal(user.status, 'pending');
  assert.equal(user.emailVerified, false);
});

test('otp: verifySignup with the correct code activates the user and consumes the OTP', async () => {
  const ctx = makeCtx();
  const su = await signup.signup(ctx, { email: 'activ@superworks.com', password: 'password12345' });
  await otp.issueOtp(ctx, { userId: su.userId, purpose: 'signup', email: 'activ@superworks.com' });
  const code = lastOtpCode(ctx);
  const out = await signup.verifySignup(ctx, { email: 'activ@superworks.com', code });
  assert.equal(out.status, 'active');
  assert.equal(out.emailVerified, true);
  const user = await users.findUserByEmail(ctx, 'activ@superworks.com');
  assert.equal(user.status, 'active');
  assert.equal(user.emailVerified, true);
  // OTP is consumed → reusing the same code fails.
  await assert.rejects(() => signup.verifySignup(ctx, { email: 'activ@superworks.com', code }), (e) => e.status === 400);
});

test('otp: wrong code fails (400), increments attempts, leaves user pending', async () => {
  const ctx = makeCtx();
  const su = await signup.signup(ctx, { email: 'wrong@superworks.com', password: 'password12345' });
  await otp.issueOtp(ctx, { userId: su.userId, purpose: 'signup', email: 'wrong@superworks.com' });
  await assert.rejects(() => signup.verifySignup(ctx, { email: 'wrong@superworks.com', code: '000000' }), (e) => e.status === 400);
  const user = await users.findUserByEmail(ctx, 'wrong@superworks.com');
  assert.equal(user.status, 'pending');
  const stored = await ctx.repo.otps.find({});
  assert.equal(stored[0].attempts, 1);
});

test('otp: expires after the TTL (400) and does not activate', async () => {
  const ctx = makeCtx();
  const su = await signup.signup(ctx, { email: 'exp@superworks.com', password: 'password12345' });
  await otp.issueOtp(ctx, { userId: su.userId, purpose: 'signup', email: 'exp@superworks.com' });
  const code = lastOtpCode(ctx);
  ctx.clock.advance(ctx.config.otp.ttlMs + 1000); // just past 5 minutes
  await assert.rejects(() => signup.verifySignup(ctx, { email: 'exp@superworks.com', code }), (e) => e.status === 400);
  const user = await users.findUserByEmail(ctx, 'exp@superworks.com');
  assert.equal(user.status, 'pending');
});

test('otp: attempt cap locks the code after 5 wrong guesses — even a correct code then fails (429)', async () => {
  const ctx = makeCtx();
  const su = await signup.signup(ctx, { email: 'cap@superworks.com', password: 'password12345' });
  await otp.issueOtp(ctx, { userId: su.userId, purpose: 'signup', email: 'cap@superworks.com' });
  const code = lastOtpCode(ctx);
  for (let i = 0; i < 5; i++) {
    await assert.rejects(() => signup.verifySignup(ctx, { email: 'cap@superworks.com', code: '111111' }), (e) => e.status === 400);
  }
  // 6th attempt is locked out regardless of correctness.
  await assert.rejects(() => signup.verifySignup(ctx, { email: 'cap@superworks.com', code }), (e) => e.status === 429);
  const user = await users.findUserByEmail(ctx, 'cap@superworks.com');
  assert.equal(user.status, 'pending');
});

test('otp: per-user send rate limit (429 after maxSendsPerWindow)', async () => {
  const ctx = makeCtx();
  const u = await users.createUser(ctx, { email: 'rl@superworks.com', password: 'password12345' });
  for (let i = 0; i < ctx.config.otp.maxSendsPerWindow; i++) {
    await otp.issueOtp(ctx, { userId: u._id, purpose: 'signup', email: 'rl@superworks.com' });
  }
  await assert.rejects(
    () => otp.issueOtp(ctx, { userId: u._id, purpose: 'signup', email: 'rl@superworks.com' }),
    (e) => e.status === 429,
  );
});

test('otp: only the newest code is valid (issuing again invalidates the old one)', async () => {
  const ctx = makeCtx();
  const su = await signup.signup(ctx, { email: 'newest@superworks.com', password: 'password12345' });
  await otp.issueOtp(ctx, { userId: su.userId, purpose: 'signup', email: 'newest@superworks.com' });
  const oldCode = lastOtpCode(ctx);
  const u = await users.findUserByEmail(ctx, 'newest@superworks.com');
  await otp.issueOtp(ctx, { userId: u._id, purpose: 'signup', email: 'newest@superworks.com' });
  const newCode = lastOtpCode(ctx);
  // Old code is now invalid...
  await assert.rejects(() => signup.verifySignup(ctx, { email: 'newest@superworks.com', code: oldCode }), (e) => e.status === 400);
  // ...new code still works (unless they happened to collide, astronomically unlikely).
  if (newCode !== oldCode) {
    const out = await signup.verifySignup(ctx, { email: 'newest@superworks.com', code: newCode });
    assert.equal(out.status, 'active');
  }
});

test('otp: verifying for an unknown email gives the same generic error (no enumeration)', async () => {
  const ctx = makeCtx();
  await assert.rejects(
    () => signup.verifySignup(ctx, { email: 'ghost@superworks.com', code: '123456' }),
    (e) => e.status === 400 && /invalid or expired/i.test(e.message),
  );
});

// ===========================================================================
// STEP 5 — login, Ed25519 JWT access token, rotating refresh, lockout
// ===========================================================================

test('tokens: access token verifies and carries identity only (no entitlements/PII)', () => {
  const ctx = makeCtx();
  const t = tokens.signAccessToken(ctx, { userId: 'u1', role: 'member', deviceId: 'dev-1' });
  const payload = tokens.verifyAccessToken(ctx, t);
  assert.equal(payload.sub, 'u1');
  assert.equal(payload.role, 'member');
  assert.equal(payload.did, 'dev-1');
  assert.ok(payload.exp > payload.iat);
  // Entitlement flags must NEVER be embedded in the token.
  assert.equal(payload.importEnabled, undefined);
  assert.equal(payload.exportEnabled, undefined);
  assert.ok(!JSON.stringify(payload).includes('@'), 'no email in token');
});

test('tokens: rejects tampered payload, wrong-key signature, and alg confusion', () => {
  const ctx = makeCtx();
  const other = makeCtx(); // different keypair
  const t = tokens.signAccessToken(ctx, { userId: 'u1', role: 'member', deviceId: 'd' });

  const [h, p, s] = t.split('.');
  const p2 = Buffer.from(JSON.stringify({ sub: 'attacker', role: 'admin', exp: 9e9, iat: 1, iss: 'managed-switcher' })).toString('base64url');
  assert.throws(() => tokens.verifyAccessToken(ctx, [h, p2, s].join('.')), (e) => e.status === 401);

  assert.throws(() => tokens.verifyAccessToken(ctx, tokens.signAccessToken(other, { userId: 'u1', role: 'member', deviceId: 'd' })), (e) => e.status === 401);

  const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const forged = [noneHeader, p, ''].join('.');
  assert.throws(() => tokens.verifyAccessToken(ctx, forged), (e) => e.status === 401);
});

test('tokens: access token expires after its TTL', () => {
  const ctx = makeCtx();
  const t = tokens.signAccessToken(ctx, { userId: 'u1', role: 'member', deviceId: 'd' });
  ctx.clock.advance(ctx.config.accessTokenTtlMs + 2000);
  assert.throws(() => tokens.verifyAccessToken(ctx, t), (e) => e.status === 401 && /expired/i.test(e.message));
});

test('login: correct credentials issue access + refresh; response has no PII/secret hash', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'lo@superworks.com', password: 'password12345' });
  const res = await auth.login(ctx, { email: 'LO@superworks.com', password: 'password12345', deviceId: 'dev-A' });
  assert.ok(res.accessToken && res.refreshToken);
  assert.equal(res.tokenType, 'Bearer');
  assert.equal(res.role, 'member');
  const payload = tokens.verifyAccessToken(ctx, res.accessToken);
  assert.equal(payload.did, 'dev-A');
  const blob = JSON.stringify(res);
  assert.ok(!blob.includes('lo@superworks.com'));
  assert.ok(!/scrypt\$/.test(blob));
});

test('login: refresh session lasts at least 60 days (session TTL follows refreshTokenTtlMs)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'sixty@superworks.com', password: 'password12345' });
  const now = ctx.clock.nowMs();
  const res = await auth.login(ctx, { email: 'sixty@superworks.com', password: 'password12345', deviceId: 'dev-60' });
  const sixtyDaysMs = 60 * 24 * 60 * 60 * 1000;
  assert.equal(ctx.config.refreshTokenTtlMs, sixtyDaysMs, 'config TTL is 60 days');
  assert.ok(ctx.config.refreshTokenTtlMs >= sixtyDaysMs, 'session must last at least 60 days');
  // Response field, measured against the injected (fake) clock, not wall time.
  assert.equal(new Date(res.refreshExpiresAt).getTime() - now, sixtyDaysMs);
  // The persisted session row's expiry (what actually gates `refresh`) matches too.
  const [session] = await ctx.repo.sessions.find({});
  assert.equal(new Date(session.expiresAt).getTime() - now, sixtyDaysMs);
  // A refresh token still exactly at the OLD 30-day mark must NOT be expired.
  ctx.clock.advance(30 * 24 * 60 * 60 * 1000 + 1000);
  const rotated = await auth.refresh(ctx, { refreshToken: res.refreshToken, deviceId: 'dev-60' });
  assert.ok(rotated.accessToken, 'refresh token issued at login is still valid past the old 30-day TTL');
});

test('login: requires a device id (400)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'nd@superworks.com', password: 'password12345' });
  await assert.rejects(() => auth.login(ctx, { email: 'nd@superworks.com', password: 'password12345' }), (e) => e.status === 400);
});

test('login: wrong password fails (401) and unknown email gives the SAME generic error', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'gen@superworks.com', password: 'password12345' });
  let m1, m2;
  await auth.login(ctx, { email: 'gen@superworks.com', password: 'nope', deviceId: 'd' }).catch(e => { m1 = e; });
  await auth.login(ctx, { email: 'ghost@superworks.com', password: 'whatever', deviceId: 'd' }).catch(e => { m2 = e; });
  assert.equal(m1.status, 401);
  assert.equal(m2.status, 401);
  assert.equal(m1.message, m2.message, 'wrong-password and unknown-email must be indistinguishable');
});

test('login: pending (unverified) account is refused (403)', async () => {
  const ctx = makeCtx();
  await users.createUser(ctx, { email: 'pend@superworks.com', password: 'password12345' }); // stays pending
  await assert.rejects(() => auth.login(ctx, { email: 'pend@superworks.com', password: 'password12345', deviceId: 'd' }), (e) => e.status === 403);
});

test('login: locks out after 5 failures, then unlocks after cooldown', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'lock@superworks.com', password: 'password12345' });
  for (let i = 0; i < 5; i++) {
    await assert.rejects(() => auth.login(ctx, { email: 'lock@superworks.com', password: 'bad', deviceId: 'd' }), (e) => e.status === 401);
  }
  // While locked, even the correct password is refused — with the SAME generic
  // 401 as a wrong password (no lockout/existence oracle).
  await assert.rejects(() => auth.login(ctx, { email: 'lock@superworks.com', password: 'password12345', deviceId: 'd' }), (e) => e.status === 401);
  ctx.clock.advance(ctx.config.loginLockout.cooldownMs + 1000);
  const res = await auth.login(ctx, { email: 'lock@superworks.com', password: 'password12345', deviceId: 'd' });
  assert.ok(res.accessToken);
});

test('login/fix: a locked account is indistinguishable from an unknown email', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'known@superworks.com', password: 'password12345' });
  for (let i = 0; i < 5; i++) {
    await auth.login(ctx, { email: 'known@superworks.com', password: 'bad', deviceId: 'd' }).catch(() => {});
  }
  let locked, unknown;
  await auth.login(ctx, { email: 'known@superworks.com', password: 'password12345', deviceId: 'd' }).catch(e => { locked = e; });
  await auth.login(ctx, { email: 'ghost@superworks.com', password: 'whatever', deviceId: 'd' }).catch(e => { unknown = e; });
  assert.equal(locked.status, unknown.status);
  assert.equal(locked.message, unknown.message);
});

test('refresh: rotates tokens; the new one works, the old one is not re-usable', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'rot@superworks.com', password: 'password12345' });
  const s1 = await auth.login(ctx, { email: 'rot@superworks.com', password: 'password12345', deviceId: 'dev-R' });
  const s2 = await auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-R' });
  assert.notEqual(s1.refreshToken, s2.refreshToken);
  assert.ok(tokens.verifyAccessToken(ctx, s2.accessToken));
  // Immediate re-submit of the rotated token (its replacement still live) is a
  // benign double-submit → 409 retry, and the family is NOT killed.
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-R' }), (e) => e.status === 409);
  const s3 = await auth.refresh(ctx, { refreshToken: s2.refreshToken, deviceId: 'dev-R' });
  assert.ok(s3.accessToken, 'the live replacement token still refreshes normally');
});

test('refresh: replay AFTER the grace window is theft → reuse-detection kills the family', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'reuse@superworks.com', password: 'password12345' });
  const s1 = await auth.login(ctx, { email: 'reuse@superworks.com', password: 'password12345', deviceId: 'dev-X' });
  const s2 = await auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-X' });
  ctx.clock.advance(ctx.config.refreshGraceMs + 1000); // past the benign-retry window
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-X' }), (e) => e.status === 401);
  // Family revoked → even the legitimate replacement no longer works.
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s2.refreshToken, deviceId: 'dev-X' }), (e) => e.status === 401);
});

test('refresh: concurrent double-refresh mints exactly one token, never a fork', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'toctou@superworks.com', password: 'password12345' });
  const s1 = await auth.login(ctx, { email: 'toctou@superworks.com', password: 'password12345', deviceId: 'dev-C' });
  const settled = await Promise.allSettled([
    auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-C' }),
    auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-C' }),
  ]);
  const ok = settled.filter(r => r.status === 'fulfilled');
  const failed = settled.filter(r => r.status === 'rejected');
  assert.equal(ok.length, 1, 'exactly one refresh wins the CAS');
  assert.equal(failed.length, 1);
  assert.equal(failed[0].reason.status, 409, 'the loser gets a benign retry, not a family kill');
  const live = await ctx.repo.sessions.find({ revokedAt: null });
  assert.equal(live.length, 1, 'no two live sibling tokens (no fork)');
});

test('refresh: is bound to the device; a mismatched device is rejected and kills the family', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'devbind@superworks.com', password: 'password12345' });
  const s1 = await auth.login(ctx, { email: 'devbind@superworks.com', password: 'password12345', deviceId: 'dev-1' });
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-2' }), (e) => e.status === 401);
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-1' }), (e) => e.status === 401);
});

test('refresh: expired refresh token is rejected (401)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'rexp@superworks.com', password: 'password12345' });
  const s1 = await auth.login(ctx, { email: 'rexp@superworks.com', password: 'password12345', deviceId: 'dev-1' });
  ctx.clock.advance(ctx.config.refreshTokenTtlMs + 1000);
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-1' }), (e) => e.status === 401);
});

test('logout: revokes the session so its refresh token stops working', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'out@superworks.com', password: 'password12345' });
  const s1 = await auth.login(ctx, { email: 'out@superworks.com', password: 'password12345', deviceId: 'dev-1' });
  await auth.logout(ctx, { refreshToken: s1.refreshToken });
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-1' }), (e) => e.status === 401);
});

// ===========================================================================
// STEP 6 — field encryption (deep): IV uniqueness, blind-index search, AAD,
//          tamper/version, low-cardinality leakage invariant
// ===========================================================================

test('crypto/deep: 1000 encryptions of the same value all use distinct IVs', () => {
  const c = createFieldCrypto(Buffer.alloc(32, 4), Buffer.alloc(32, 5));
  const ivs = new Set();
  for (let i = 0; i < 1000; i++) {
    const raw = Buffer.from(c.encrypt('same-plaintext'), 'base64');
    ivs.add(raw.subarray(1, 13).toString('hex')); // bytes after the version byte
  }
  assert.equal(ivs.size, 1000, 'every IV must be unique (no nonce reuse)');
});

test('crypto/deep: blind-index enables equality search over encrypted data', () => {
  const c = createFieldCrypto(Buffer.alloc(32, 1), Buffer.alloc(32, 2));
  const emails = ['alice@x.com', 'bob@x.com', 'carol@x.com'];
  const table = emails.map(e => ({ emailIdx: c.blindIndex(e), emailEnc: c.encrypt(e) }));
  // Search WITHOUT any plaintext stored:
  const query = c.blindIndex('bob@x.com');
  const hit = table.find(r => r.emailIdx === query);
  assert.ok(hit, 'blind index should locate the encrypted row');
  assert.equal(c.decrypt(hit.emailEnc), 'bob@x.com');
  // A non-member yields no hit.
  assert.equal(table.find(r => r.emailIdx === c.blindIndex('dave@x.com')), undefined);
});

test('crypto/deep: AAD binds a ciphertext to its context (cannot be relocated)', () => {
  const c = createFieldCrypto(Buffer.alloc(32, 6), Buffer.alloc(32, 7));
  const enc = c.encrypt('secret-value', 'field:ipEnc|user:u1');
  assert.equal(c.decrypt(enc, 'field:ipEnc|user:u1'), 'secret-value');
  // Wrong AAD (e.g., moved to another user/field) → auth failure.
  assert.throws(() => c.decrypt(enc, 'field:ipEnc|user:u2'));
  // Missing AAD when one was used → auth failure.
  assert.throws(() => c.decrypt(enc));
});

test('crypto/deep: rejects bad version byte and truncated ciphertext', () => {
  const c = createFieldCrypto(Buffer.alloc(32, 8), Buffer.alloc(32, 9));
  const raw = Buffer.from(c.encrypt('x'), 'base64');
  raw[0] = 0x09; // unknown version
  assert.throws(() => c.decrypt(raw.toString('base64')), /version/i);
  assert.throws(() => c.decrypt(Buffer.alloc(5).toString('base64')), /too short/i);
});

test('crypto/deep: blind index leaks equality (invariant) — only for high-cardinality fields', () => {
  const c = createFieldCrypto(Buffer.alloc(32, 1), Buffer.alloc(32, 2));
  // Same value → same index. This is WHY low-cardinality fields (role, flags)
  // must never be blind-indexed: it would reveal the value by grouping.
  assert.equal(c.blindIndex('member'), c.blindIndex('member'));
  assert.notEqual(c.blindIndex('member'), c.blindIndex('admin'));
});

// ===========================================================================
// STEP 7 — hash chain primitive + live entitlements + admin mutation ledger
// ===========================================================================

test('hashchain: canonicalJson is key-order independent and stable', () => {
  assert.equal(hashchain.canonicalJson({ a: 1, b: 2 }), hashchain.canonicalJson({ b: 2, a: 1 }));
  assert.equal(hashchain.canonicalJson({ x: [3, { z: 1, y: 2 }] }), '{"x":[3,{"y":2,"z":1}]}');
  assert.throws(() => hashchain.canonicalJson(Infinity));
});

test('hashchain: appendChained builds a verifiable linked chain', async () => {
  const ctx = makeCtx();
  for (let i = 0; i < 5; i++) {
    await hashchain.appendChained(ctx, ctx.repo.permissionChanges, ctx.config.auditHmacKey, { n: i });
  }
  const entries = await ctx.repo.permissionChanges.find({});
  assert.equal(entries.length, 5);
  assert.deepEqual(entries.map(e => e.seq), [1, 2, 3, 4, 5]);
  assert.equal(entries[0].prevHash, hashchain.GENESIS);
  assert.equal(entries[1].prevHash, entries[0].entryHash);
  const res = hashchain.verifyChain(entries, ctx.config.auditHmacKey);
  assert.equal(res.ok, true);
  assert.equal(res.count, 5);
});

test('hashchain: verify detects a mutated field (entry_hash_mismatch)', async () => {
  const ctx = makeCtx();
  await hashchain.appendChained(ctx, ctx.repo.permissionChanges, ctx.config.auditHmacKey, { n: 1, note: 'ok' });
  await hashchain.appendChained(ctx, ctx.repo.permissionChanges, ctx.config.auditHmacKey, { n: 2, note: 'ok' });
  const entries = await ctx.repo.permissionChanges.find({});
  entries[0].note = 'tampered'; // attacker edits a stored core field
  const res = hashchain.verifyChain(entries, ctx.config.auditHmacKey);
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'entry_hash_mismatch');
  assert.equal(res.seq, 1);
});

test('hashchain: verify detects a broken prev-link', async () => {
  const ctx = makeCtx();
  await hashchain.appendChained(ctx, ctx.repo.permissionChanges, ctx.config.auditHmacKey, { n: 1 });
  await hashchain.appendChained(ctx, ctx.repo.permissionChanges, ctx.config.auditHmacKey, { n: 2 });
  const entries = await ctx.repo.permissionChanges.find({});
  entries[1].prevHash = 'GENESIS'; // relink to genesis
  const res = hashchain.verifyChain(entries, ctx.config.auditHmacKey);
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'prev_hash_mismatch');
});

test('hashchain: concurrent appends produce a gap-free, verifiable chain (seq race)', async () => {
  const ctx = makeCtx();
  const N = 20;
  await Promise.all(Array.from({ length: N }, (_, i) =>
    hashchain.appendChained(ctx, ctx.repo.permissionChanges, ctx.config.auditHmacKey, { n: i })));
  const entries = await ctx.repo.permissionChanges.find({});
  assert.equal(entries.length, N);
  assert.deepEqual(entries.map(e => e.seq), Array.from({ length: N }, (_, i) => i + 1));
  assert.equal(hashchain.verifyChain(entries, ctx.config.auditHmacKey).ok, true);
});

test('entitlements: gates are read LIVE — admin revoke takes effect immediately', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'member@superworks.com', password: 'password12345' });

  // Grant export, then confirm allowed.
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'exportEnabled', value: true });
  await entitlements.assertCan(ctx, member._id, 'export'); // no throw

  // Revoke; the very next gated call is denied (no token refresh needed).
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'exportEnabled', value: false });
  await assert.rejects(() => entitlements.assertCan(ctx, member._id, 'export'), (e) => e.status === 403);
});

test('entitlements: import gate denies by default and respects expiry', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'a2@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm2@superworks.com', password: 'password12345' });
  await assert.rejects(() => entitlements.assertCan(ctx, member._id, 'import'), (e) => e.status === 403);

  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'importEnabled', value: true });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'entitlementExpiresAt', value: new Date(ctx.clock.nowMs() + 60000) });
  await entitlements.assertCan(ctx, member._id, 'import'); // allowed before expiry

  ctx.clock.advance(61000); // past expiry
  await assert.rejects(() => entitlements.assertCan(ctx, member._id, 'import'), (e) => e.status === 403);
});

test('entitlements: only an admin may mutate flags (member is refused 403)', async () => {
  const ctx = makeCtx();
  const member = await makeActiveUser(ctx, { email: 'nm@superworks.com', password: 'password12345' });
  const victim = await makeActiveUser(ctx, { email: 'vic@superworks.com', password: 'password12345' });
  await assert.rejects(
    () => entitlements.setEntitlement(ctx, { adminId: member._id, targetUserId: victim._id, field: 'exportEnabled', value: true }),
    (e) => e.status === 403,
  );
  // No permission_changes entry was written.
  assert.equal((await ctx.repo.permissionChanges.find({})).length, 0);
  // And the flag stayed off.
  assert.equal((await entitlements.getLiveEntitlements(ctx, victim._id)).exportEnabled, false);
});

test('entitlements: mutations are recorded in a verifiable permission_changes chain', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'a3@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm3@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'importEnabled', value: true });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'exportEnabled', value: true });
  const entries = await ctx.repo.permissionChanges.find({});
  assert.equal(entries.length, 2);
  assert.equal(entries[0].field, 'importEnabled');
  assert.equal(entries[0].from, false);
  assert.equal(entries[0].to, true);
  assert.equal(entries[0].adminId, admin._id);
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
  // Tamper one record → chain verify fails.
  entries[1].to = false;
  assert.equal(hashchain.verifyChain(entries, ctx.config.auditHmacKey).ok, false);
});

// ===========================================================================
// STEP 8 — audit ledger: append-only chain, serverTs UTC, anchors, verify
// ===========================================================================

async function recordSome(ctx, n, base = {}) {
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i, ...base }));
  }
  return out;
}

test('audit: recordEvent stamps an authoritative UTC serverTs and ignores clientTs for ordering', async () => {
  const ctx = makeCtx();
  const r = await audit.recordEvent(ctx, { eventType: 'login', userId: 'u1', clientTs: '1999-01-01T00:00:00Z' });
  assert.equal(r.seq, 1);
  const [e] = await ctx.repo.auditEvents.find({});
  assert.ok(e.serverTs instanceof Date);
  assert.equal(e.serverTs.getTime(), ctx.clock.nowMs()); // server clock wins
  assert.equal(e.clientTs, '1999-01-01T00:00:00Z');      // recorded, untrusted
});

test('audit: rejects unknown event types', async () => {
  const ctx = makeCtx();
  await assert.rejects(() => audit.recordEvent(ctx, { eventType: 'not_a_real_event' }), (e) => e.status === 400);
});

test('audit: builds a monotonic, gap-free, verifiable chain', async () => {
  const ctx = makeCtx();
  await recordSome(ctx, 6);
  const events = await ctx.repo.auditEvents.find({});
  assert.deepEqual(events.map(e => e.seq), [1, 2, 3, 4, 5, 6]);
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true);
});

test('audit: verify detects a tampered event', async () => {
  const ctx = makeCtx();
  await recordSome(ctx, 4);
  const events = await ctx.repo.auditEvents.find({});
  events[2].userId = 'attacker'; // edit a stored field
  const res = audit.verifyEvents(events, [], { hmacKey: ctx.config.auditHmacKey, anchorPublicKey: ctx.config.anchorPublicKey });
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'entry_hash_mismatch');
  assert.equal(res.seq, 3);
});

test('audit: anchorNow signs the head; verify passes and re-anchor is a no-op until head moves', async () => {
  const ctx = makeCtx();
  await recordSome(ctx, 5);
  const a1 = await audit.anchorNow(ctx);
  assert.equal(a1.seqHigh, 5);
  assert.ok(a1.signature);
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true);
  // No new events → re-anchor returns the same anchor.
  const a2 = await audit.anchorNow(ctx);
  assert.equal(a2.seqHigh, 5);
  assert.equal((await ctx.repo.auditAnchors.find({})).length, 1);
  // New event → a fresh anchor is created.
  await recordSome(ctx, 1);
  const a3 = await audit.anchorNow(ctx);
  assert.equal(a3.seqHigh, 6);
});

test('audit: a forged anchor signature is detected', async () => {
  const ctx = makeCtx();
  await recordSome(ctx, 3);
  await audit.anchorNow(ctx);
  const events = await ctx.repo.auditEvents.find({});
  const anchors = await ctx.repo.auditAnchors.find({});
  anchors[0].headHash = Buffer.from('forged-head').toString('base64'); // move the anchor
  const res = audit.verifyEvents(events, anchors, { hmacKey: ctx.config.auditHmacKey, anchorPublicKey: ctx.config.anchorPublicKey });
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'anchor_signature_invalid');
});

test('audit: verifies from the last retained anchor forward after pruning (TTL simulation)', async () => {
  const ctx = makeCtx();
  await recordSome(ctx, 5);
  const a5 = await audit.anchorNow(ctx); // anchor at seq 5
  await recordSome(ctx, 3);              // events 6,7,8
  const allEvents = await ctx.repo.auditEvents.find({});
  const anchors = await ctx.repo.auditAnchors.find({});
  // Simulate TTL pruning of events 1..5; only 6,7,8 remain.
  const retained = allEvents.filter(e => e.seq > 5);
  assert.deepEqual(retained.map(e => e.seq), [6, 7, 8]);
  const res = audit.verifyEvents(retained, anchors, { hmacKey: ctx.config.auditHmacKey, anchorPublicKey: ctx.config.anchorPublicKey });
  assert.equal(res.ok, true);
  assert.equal(res.headSeq, 8);
  assert.ok(a5); // the seq-5 anchor is what makes the pruned tail provable
});

test('audit: pruned tail with a broken link is still caught', async () => {
  const ctx = makeCtx();
  await recordSome(ctx, 5);
  await audit.anchorNow(ctx);
  await recordSome(ctx, 3);
  const allEvents = await ctx.repo.auditEvents.find({});
  const anchors = await ctx.repo.auditAnchors.find({});
  const retained = allEvents.filter(e => e.seq > 5);
  retained[0].prevHash = 'GENESIS'; // break the link back to the anchor
  const res = audit.verifyEvents(retained, anchors, { hmacKey: ctx.config.auditHmacKey, anchorPublicKey: ctx.config.anchorPublicKey });
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'prev_hash_mismatch');
});

test('audit: idempotent ingestion — the same idempotencyKey is stored once', async () => {
  const ctx = makeCtx();
  const r1 = await audit.recordEvent(ctx, { eventType: 'export', userId: 'u1', idempotencyKey: 'evt-abc' });
  const r2 = await audit.recordEvent(ctx, { eventType: 'export', userId: 'u1', idempotencyKey: 'evt-abc' });
  assert.equal(r1.idempotent, false);
  assert.equal(r2.idempotent, true);
  assert.equal(r1.seq, r2.seq);
  assert.equal((await ctx.repo.auditEvents.find({})).length, 1);
});

test('audit: concurrent duplicate idempotency keys still store exactly one', async () => {
  const ctx = makeCtx();
  const results = await Promise.all(
    Array.from({ length: 10 }, () => audit.recordEvent(ctx, { eventType: 'import', userId: 'u1', idempotencyKey: 'same-key' })),
  );
  const seqs = new Set(results.map(r => r.seq));
  assert.equal(seqs.size, 1, 'all concurrent writes resolve to a single stored event');
  assert.equal((await ctx.repo.auditEvents.find({})).length, 1);
});

test('audit: many concurrent DISTINCT events produce a gap-free verifiable chain', async () => {
  const ctx = makeCtx();
  await Promise.all(Array.from({ length: 25 }, (_, i) =>
    audit.recordEvent(ctx, { eventType: 'switch', userId: 'u' + i, idempotencyKey: 'k' + i })));
  const events = await ctx.repo.auditEvents.find({});
  assert.deepEqual(events.map(e => e.seq), Array.from({ length: 25 }, (_, i) => i + 1));
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true);
});

// ===========================================================================
// STEP 9 — request security: Host/Origin/CT, rate limits, error hygiene,
//          auth gating, idempotency
// ===========================================================================

test('http: health check needs no auth', async () => {
  const ctx = makeCtx();
  const res = await routes.handleRequest(ctx, req('GET', '/health'));
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
});

test('http: blocks unexpected Host (403)', async () => {
  const ctx = makeCtx();
  const res = await routes.handleRequest(ctx, req('GET', '/health', { headers: { host: 'evil.example.com' } }));
  assert.equal(res.status, 403);
});

test('http: blocks cross-origin requests (403)', async () => {
  const ctx = makeCtx();
  const res = await routes.handleRequest(ctx, req('GET', '/health', { headers: { host: '127.0.0.1', origin: 'http://evil.example.com' } }));
  assert.equal(res.status, 403);
});

test('http: state-changing requests must be application/json (403)', async () => {
  const ctx = makeCtx();
  const res = await routes.handleRequest(ctx, req('POST', '/auth/login', { headers: { 'content-type': 'text/plain' }, body: {} }));
  assert.equal(res.status, 403);
});

test('http: unknown route → 404', async () => {
  const ctx = makeCtx();
  const res = await routes.handleRequest(ctx, req('GET', '/nope'));
  assert.equal(res.status, 404);
});

test('http: full signup → pending (cannot log in) → admin approve → login flow, responses carry no PII/secret', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'flowadmin@superworks.com', password: 'password12345', role: 'admin' });
  const s = await routes.handleRequest(ctx, req('POST', '/auth/signup', { body: { email: 'flow@superworks.com', password: 'password12345' } }));
  assert.equal(s.status, 201);
  assert.ok(!JSON.stringify(s.body).includes('flow@superworks.com'));
  const userId = s.body.userId;
  // A pending user cannot sign in until an admin approves.
  const pre = await routes.handleRequest(ctx, req('POST', '/auth/login', { body: { email: 'flow@superworks.com', password: 'password12345', deviceId: 'dev-1' } }));
  assert.equal(pre.status, 403);
  // Admin approves → the account becomes active.
  const adminBearer = await bearerFor(ctx, 'flowadmin@superworks.com', 'password12345', 'dev-admin');
  const ap = await routes.handleRequest(ctx, req('POST', '/admin/users/approve', { headers: { authorization: adminBearer }, body: { targetUserId: userId } }));
  assert.equal(ap.status, 200);
  // Now the login works.
  const l = await routes.handleRequest(ctx, req('POST', '/auth/login', { body: { email: 'flow@superworks.com', password: 'password12345', deviceId: 'dev-1' } }));
  assert.equal(l.status, 200);
  assert.ok(l.body.accessToken && l.body.refreshToken);
  assert.ok(!/scrypt\$/.test(JSON.stringify(l.body)));
});

test('http: auth-required route rejects missing/invalid bearer (401) and accepts a valid one', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'me@superworks.com', password: 'password12345' });
  const noAuth = await routes.handleRequest(ctx, req('GET', '/entitlements/me'));
  assert.equal(noAuth.status, 401);
  const badAuth = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: 'Bearer not.a.jwt' } }));
  assert.equal(badAuth.status, 401);
  assert.ok(!JSON.stringify(badAuth.body).includes('not.a.jwt'), 'error must not echo the token');
  const bearer = await bearerFor(ctx, 'me@superworks.com', 'password12345');
  const ok = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer } }));
  assert.equal(ok.status, 200);
  assert.equal(ok.body.importEnabled, false);
  assert.equal(ok.body.exportEnabled, false);
});

test('http: admin-only route refuses a member (403) and allows an admin (200)', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'ad@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'mb@superworks.com', password: 'password12345' });
  const memberBearer = await bearerFor(ctx, 'mb@superworks.com', 'password12345');
  const denied = await routes.handleRequest(ctx, req('POST', '/admin/entitlements', {
    headers: { authorization: memberBearer },
    body: { targetUserId: member._id, field: 'exportEnabled', value: true },
  }));
  assert.equal(denied.status, 403);

  const adminBearer = await bearerFor(ctx, 'ad@superworks.com', 'password12345', 'dev-admin');
  const ok = await routes.handleRequest(ctx, req('POST', '/admin/entitlements', {
    headers: { authorization: adminBearer },
    body: { targetUserId: member._id, field: 'exportEnabled', value: true },
  }));
  assert.equal(ok.status, 200);
  assert.equal((await entitlements.getLiveEntitlements(ctx, member._id)).exportEnabled, true);
});

test('http: the HTTP per-route rate limiter is gone — no throttling on repeated requests', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'nothrottle@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'nothrottle@superworks.com', 'password12345', 'dev-nt');
  // GET /entitlements/me has no account-lockout/OTP/quota control on it, so if
  // every one of these 150 requests (well beyond the old 120/min HTTP limit)
  // comes back 200, the throttle is confirmed removed, not merely raised.
  const results = [];
  for (let i = 0; i < 150; i++) {
    results.push(await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '9.9.9.9' })));
  }
  assert.ok(results.every(r => r.status === 200), 'no request was throttled by an HTTP rate limiter');
  assert.equal(routes.RATE_LIMITS, undefined, 'the per-route rate-limit table no longer exists');
});

test('http: error hygiene — 5xx bodies are generic; curated 4xx messages pass through; no secret leak', () => {
  const ctx = makeCtx();
  const { httpError } = require('./lib/errors');

  const client = routes.toErrorResponse(ctx, httpError(400, 'Enter a valid email address.'), { method: 'POST', path: '/x' });
  assert.equal(client.status, 400);
  assert.equal(client.body.error, 'Enter a valid email address.');

  const internal = routes.toErrorResponse(ctx, new Error('connect ECONNREFUSED mongodb+srv://user:pass@host'), { method: 'POST', path: '/x' });
  assert.equal(internal.status, 500);
  assert.ok(!/mongodb|pass|ECONNREFUSED/.test(JSON.stringify(internal.body)), 'internal error details must not leak');
});

test('http: audit ingestion is idempotent by header and forces server-side identity', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'em@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'em@superworks.com', 'password12345', 'dev-emit');
  const body = { eventType: 'switch', userId: 'spoofed-user', deviceId: 'spoofed-device' };
  const headers = { authorization: bearer, 'idempotency-key': 'evt-1' };
  const r1 = await routes.handleRequest(ctx, req('POST', '/audit/events', { headers, body }));
  const r2 = await routes.handleRequest(ctx, req('POST', '/audit/events', { headers, body }));
  assert.equal(r1.status, 200);
  assert.equal(r2.body.idempotent, true);
  const stored = await ctx.repo.auditEvents.find({});
  assert.equal(stored.length, 1, 'same idempotency key → one event');
  // The client cannot spoof identity — server stamps it from the token.
  assert.notEqual(stored[0].userId, 'spoofed-user');
  assert.notEqual(stored[0].deviceId, 'spoofed-device');
  assert.equal(stored[0].deviceId, 'dev-emit');
});

// ===========================================================================
// TASK 13 — notice_accepted ingestion wires the dead noticeAcceptedAt/
// noticeVersion user fields (spec §6.8 gap), additively, without touching the
// audit hash chain.
// ===========================================================================

test('http: ingesting a notice_accepted event wires user.noticeAcceptedAt/noticeVersion, and the audit chain still verifies', async () => {
  const ctx = makeCtx();
  const created = await makeActiveUser(ctx, { email: 'notice1@superworks.com', password: 'password12345' });
  assert.equal(created.noticeAcceptedAt, null, 'starts null (the dead field, pre-Task-13)');
  assert.equal(created.noticeVersion, null);

  const bearer = await bearerFor(ctx, 'notice1@superworks.com', 'password12345', 'dev-notice-1');
  const res = await routes.handleRequest(ctx, req('POST', '/audit/events', {
    headers: { authorization: bearer },
    body: { eventType: 'notice_accepted', clientTs: '2026-07-17T00:00:00.000Z', noticeVersion: '2' },
  }));
  assert.equal(res.status, 200);

  const updated = await ctx.repo.users.findById(created._id);
  assert.ok(updated.noticeAcceptedAt, 'noticeAcceptedAt is now populated');
  assert.equal(updated.noticeVersion, '2', 'noticeVersion is taken from the event payload');

  // Additive-only: the stored audit event itself carries NO noticeVersion field (it is
  // not in audit.js's CORE_FIELDS), and the hash chain is still byte-compatible/verifies.
  const stored = await ctx.repo.auditEvents.find({});
  assert.equal(stored.length, 1);
  assert.equal(stored[0].eventType, 'notice_accepted');
  assert.equal(stored[0].noticeVersion, undefined, 'noticeVersion never enters the hashed audit core');
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true, 'the audit chain still verifies');
});

test('http: notice_accepted without a noticeVersion in the payload still stamps noticeAcceptedAt but leaves noticeVersion untouched', async () => {
  const ctx = makeCtx();
  const created = await makeActiveUser(ctx, { email: 'notice2@superworks.com', password: 'password12345' });
  await ctx.repo.users.updateById(created._id, { noticeVersion: '1' }); // simulate a prior acceptance already on file

  const bearer = await bearerFor(ctx, 'notice2@superworks.com', 'password12345', 'dev-notice-2');
  const res = await routes.handleRequest(ctx, req('POST', '/audit/events', {
    headers: { authorization: bearer },
    body: { eventType: 'notice_accepted' },
  }));
  assert.equal(res.status, 200);

  const updated = await ctx.repo.users.findById(created._id);
  assert.ok(updated.noticeAcceptedAt, 'noticeAcceptedAt is still stamped from server receive time');
  assert.equal(updated.noticeVersion, '1', 'left alone when absent from the payload, never overwritten with null/undefined');
});

test('http: other client event types (e.g. login) never touch noticeAcceptedAt/noticeVersion', async () => {
  const ctx = makeCtx();
  const created = await makeActiveUser(ctx, { email: 'notice3@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'notice3@superworks.com', 'password12345', 'dev-notice-3');
  const res = await routes.handleRequest(ctx, req('POST', '/audit/events', {
    headers: { authorization: bearer },
    body: { eventType: 'login' },
  }));
  assert.equal(res.status, 200);
  const updated = await ctx.repo.users.findById(created._id);
  assert.equal(updated.noticeAcceptedAt, null);
  assert.equal(updated.noticeVersion, null);
});

test('config: DEVICECRED_UPLOAD_ENABLED backend echo defaults to true and is informational only', () => {
  assert.equal(loadConfig(fullEnv()).devicecredUploadEnabled, true);
  assert.equal(loadConfig(fullEnv({ DEVICECRED_UPLOAD_ENABLED: 'false' })).devicecredUploadEnabled, false);
  assert.equal(loadConfig(fullEnv({ DEVICECRED_UPLOAD_ENABLED: 'true' })).devicecredUploadEnabled, true);
});

test('http: admin can verify the audit chain over HTTP', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'av@superworks.com', password: 'password12345', role: 'admin' });
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'u1' });
  const bearer = await bearerFor(ctx, 'av@superworks.com', 'password12345', 'dev-v');
  const res = await routes.handleRequest(ctx, req('GET', '/admin/audit/verify', { headers: { authorization: bearer } }));
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
});

// ===========================================================================
// STEP 10 — seed/admin CLI building blocks (createAdmin, env template)
// ===========================================================================

test('admin: createAdmin makes an active, verified, entitled admin who can log in', async () => {
  const ctx = makeCtx();
  assert.equal(await admin.hasAdmin(ctx), false);
  const res = await admin.createAdmin(ctx, { email: 'boss@superworks.com', password: 'password12345' });
  assert.equal(res.role, 'admin');
  assert.ok(res.userId);
  assert.equal(await admin.hasAdmin(ctx), true);

  const u = await users.findUserByEmail(ctx, 'boss@superworks.com');
  assert.equal(u.role, 'admin');
  assert.equal(u.status, 'active');
  assert.equal(u.emailVerified, true);
  assert.equal(u.importEnabled, true);
  assert.equal(u.exportEnabled, true);

  // The admin can authenticate immediately (no OTP dance).
  const login = await auth.login(ctx, { email: 'boss@superworks.com', password: 'password12345', deviceId: 'seed' });
  assert.ok(login.accessToken);
  assert.equal(login.role, 'admin');
});

test('admin: createAdmin rejects a duplicate email (409)', async () => {
  const ctx = makeCtx();
  await admin.createAdmin(ctx, { email: 'boss@superworks.com', password: 'password12345' });
  await assert.rejects(
    () => admin.createAdmin(ctx, { email: 'BOSS@superworks.com', password: 'password12345' }),
    (e) => e.status === 409,
  );
});

// ===========================================================================
// STEP 10b — createManagedUser (admin directly provisions an employee)
// ===========================================================================

test('admin: createManagedUser makes an ACTIVE + verified member with import/export OFF by default, who can log in immediately (no OTP)', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'boss2@superworks.com', password: 'password12345' });

  const res = await admin.createManagedUser(ctx, {
    adminId: boss.userId, email: 'emp1@superworks.com', password: 'password12345',
  });
  assert.ok(res.userId);
  assert.equal(res.role, 'member');
  assert.equal(res.status, 'active');
  assert.equal(res.importEnabled, false);
  assert.equal(res.exportEnabled, false);

  const u = await users.findUserByEmail(ctx, 'emp1@superworks.com');
  assert.equal(u.status, 'active');
  assert.equal(u.emailVerified, true);
  assert.equal(u.importEnabled, false);
  assert.equal(u.exportEnabled, false);

  // No OTP dance — the employee can authenticate right away.
  const login = await auth.login(ctx, { email: 'emp1@superworks.com', password: 'password12345', deviceId: 'emp-dev' });
  assert.ok(login.accessToken);
  assert.equal(login.role, 'member');
});

test('admin: createManagedUser with importEnabled/exportEnabled true grants both live and records two AUDITED, chain-verifiable ledger entries', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'boss3@superworks.com', password: 'password12345' });

  const res = await admin.createManagedUser(ctx, {
    adminId: boss.userId, email: 'emp2@superworks.com', password: 'password12345',
    importEnabled: true, exportEnabled: true,
  });
  assert.equal(res.importEnabled, true);
  assert.equal(res.exportEnabled, true);

  const live = await entitlements.getLiveEntitlements(ctx, res.userId);
  assert.equal(live.importEnabled, true);
  assert.equal(live.exportEnabled, true);

  const changes = await ctx.repo.permissionChanges.find({ targetUserId: res.userId });
  assert.equal(changes.length, 2, 'the two initial grants are audited (unlike createAdmin, which grants silently)');
  assert.deepEqual(changes.map((c) => c.field).sort(), ['exportEnabled', 'importEnabled']);
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true, 'append-only — chain still verifies');
});

test('admin: createManagedUser with a non-default initial status applies it through the audited path', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'boss4@superworks.com', password: 'password12345' });

  const res = await admin.createManagedUser(ctx, {
    adminId: boss.userId, email: 'emp3@superworks.com', password: 'password12345', status: 'suspended',
  });
  assert.equal(res.status, 'suspended');
  const u = await users.findUserByEmail(ctx, 'emp3@superworks.com');
  assert.equal(u.status, 'suspended');

  const changes = await ctx.repo.permissionChanges.find({ targetUserId: res.userId });
  assert.deepEqual(changes.map((c) => c.field), ['status']);
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
});

test('admin: createManagedUser role:"admin" creates a user who immediately passes requireAdmin', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'boss5@superworks.com', password: 'password12345' });

  const res = await admin.createManagedUser(ctx, {
    adminId: boss.userId, email: 'emp4@superworks.com', password: 'password12345', role: 'admin',
  });
  assert.equal(res.role, 'admin');
  await entitlements.requireAdmin(ctx, res.userId); // does not throw
});

// F3 provenance: WHO created this user.
test('admin: createManagedUser sets createdBy = the creating admin\'s id on the user doc and in the return payload', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'bosscb@superworks.com', password: 'password12345' });

  const res = await admin.createManagedUser(ctx, {
    adminId: boss.userId, email: 'empcb@superworks.com', password: 'password12345',
  });
  assert.equal(res.createdBy, boss.userId);
  const u = await users.findUserByEmail(ctx, 'empcb@superworks.com');
  assert.equal(u.createdBy, boss.userId);
});

test('admin: approveUser activates a pending self-signup (audited) so it can then log in', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'apboss@superworks.com', password: 'password12345' });
  const signed = await signup.signup(ctx, { email: 'apuser@superworks.com', password: 'password12345' });
  assert.equal(signed.status, 'pending');
  // Cannot log in while pending.
  await assert.rejects(() => auth.login(ctx, { email: 'apuser@superworks.com', password: 'password12345', deviceId: 'd1' }), (e) => e.status === 403);

  const before = (await ctx.repo.permissionChanges.find({})).length;
  const out = await admin.approveUser(ctx, { adminId: boss.userId, targetUserId: signed.userId });
  assert.equal(out.status, 'active');
  assert.equal(out.emailVerified, true);
  const u = await users.findUserByEmail(ctx, 'apuser@superworks.com');
  assert.equal(u.status, 'active');
  assert.equal(u.emailVerified, true);
  assert.equal((await ctx.repo.permissionChanges.find({})).length, before + 1, 'the status change is ledgered');
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
  // Now the login succeeds.
  const res = await auth.login(ctx, { email: 'apuser@superworks.com', password: 'password12345', deviceId: 'd1' });
  assert.ok(res.accessToken);
});

test('admin: rejectUser sets status rejected (audited); the account can never log in', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'rjboss@superworks.com', password: 'password12345' });
  const signed = await signup.signup(ctx, { email: 'rjuser@superworks.com', password: 'password12345' });

  const out = await admin.rejectUser(ctx, { adminId: boss.userId, targetUserId: signed.userId });
  assert.equal(out.status, 'rejected');
  const u = await users.findUserByEmail(ctx, 'rjuser@superworks.com');
  assert.equal(u.status, 'rejected');
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
  await assert.rejects(
    () => auth.login(ctx, { email: 'rjuser@superworks.com', password: 'password12345', deviceId: 'd1' }),
    (e) => e.status === 403 && /declined/i.test(e.message),
  );
});

test('admin: approveUser / rejectUser require an admin caller (a member is refused 403)', async () => {
  const ctx = makeCtx();
  const member = await makeActiveUser(ctx, { email: 'notadmin@superworks.com', password: 'password12345' });
  const signed = await signup.signup(ctx, { email: 'pv@superworks.com', password: 'password12345' });
  await assert.rejects(() => admin.approveUser(ctx, { adminId: member._id, targetUserId: signed.userId }), (e) => e.status === 403);
  await assert.rejects(() => admin.rejectUser(ctx, { adminId: member._id, targetUserId: signed.userId }), (e) => e.status === 403);
});

test('admin: createManagedUser base create stays un-ledgered — createdBy adds no permission_changes row for a default (no grants) create', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'bossledger@superworks.com', password: 'password12345' });
  const before = (await ctx.repo.permissionChanges.find({})).length;
  await admin.createManagedUser(ctx, { adminId: boss.userId, email: 'empledger@superworks.com', password: 'password12345' });
  const after = (await ctx.repo.permissionChanges.find({})).length;
  assert.equal(after, before, 'a default create (no import/export/status grants) appends no ledger row');
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
});

test('admin: createManagedUser rejects a duplicate email (409)', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'boss6@superworks.com', password: 'password12345' });
  await admin.createManagedUser(ctx, { adminId: boss.userId, email: 'dupe@superworks.com', password: 'password12345' });
  await assert.rejects(
    () => admin.createManagedUser(ctx, { adminId: boss.userId, email: 'DUPE@superworks.com', password: 'password12345' }),
    (e) => e.status === 409,
  );
});

test('admin: createManagedUser rejects a weak password (400)', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'boss7@superworks.com', password: 'password12345' });
  await assert.rejects(
    () => admin.createManagedUser(ctx, { adminId: boss.userId, email: 'weak@superworks.com', password: 'short' }),
    (e) => e.status === 400,
  );
});

test('admin: createManagedUser refuses a non-admin caller (403) and creates no user', async () => {
  const ctx = makeCtx();
  const plain = await users.createUser(ctx, { email: 'plainadmin@superworks.com', password: 'password12345' });
  await ctx.repo.users.updateById(plain._id, { status: 'active', emailVerified: true });
  await assert.rejects(
    () => admin.createManagedUser(ctx, { adminId: plain._id, email: 'shouldnotexist@superworks.com', password: 'password12345' }),
    (e) => e.status === 403,
  );
  assert.equal(await users.findUserByEmail(ctx, 'shouldnotexist@superworks.com'), null);
});

test('config: buildEnvTemplate emits every required var and round-trips through loadConfig', () => {
  const { text } = buildEnvTemplate();
  for (const name of [
    'MONGODB_URI', 'FIELD_ENC_KEY', 'BLIND_INDEX_KEY', 'AUDIT_HMAC_KEY',
    'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY', 'ANCHOR_PRIVATE_KEY', 'ANCHOR_PUBLIC_KEY',
    'GMAIL_USER', 'GMAIL_APP_PASSWORD', 'PORT',
  ]) {
    assert.ok(text.includes(name), `template should mention ${name}`);
  }
  // The generated key material actually loads (PEM escaping + base64 lengths OK).
  const parsed = parseEnvFile(text);
  const cfg = loadConfig(parsed);
  assert.equal(cfg.jwtPrivateKey.asymmetricKeyType, 'ed25519');
  assert.equal(cfg.fieldEncKey.length, 32);
});

// ===========================================================================
// HARDENING — no secret/PII leak into server-side logs on unexpected 5xx
// ===========================================================================

test('hygiene: unexpected 5xx redacts credentials/secrets before logging', () => {
  const logs = [];
  const ctx = makeCtx({ logger: { info() {}, error: (m) => logs.push(m) } });
  const res = routes.toErrorResponse(
    ctx,
    new Error('MongoServerError: auth failed for mongodb+srv://appuser:s3cr3tPASS@cluster0.mongodb.net/db'),
    { method: 'POST', path: '/auth/login' },
  );
  assert.equal(res.status, 500);
  assert.equal(res.body.error, 'Something went wrong. Please try again.');
  assert.equal(logs.length, 1);
  assert.ok(!logs[0].includes('s3cr3tPASS'), 'password must not reach the log');
  assert.ok(!logs[0].includes('appuser:s3cr3tPASS'), 'credentials must be redacted');
  // The route is still logged for debuggability.
  assert.ok(logs[0].includes('/auth/login'));
});

// SEC-1 (red-team, Important): cli.js's and server.js's top-level
// `main().catch(err => console.error(err.message))` handlers logged err.message
// RAW — unlike every other logger.error call in the backend, which wraps
// redactSensitive first. A Mongo connect/URI error can embed MONGODB_URI WITH
// credentials, so an unhandled startup failure could print the connection
// string (password and all) straight to the process's stderr/log. Both
// catches are now wrapped in redactSensitive (see cli.js/server.js). The
// top-level `if (require.main === module)` catch itself isn't reachable via
// `require(...)` (it never runs when the file is merely required as a
// module), so this test instead pins down the exact behavior the fix relies
// on: redactSensitive fully removes a Mongo credential — INCLUDING a password
// that itself contains a literal "@" (which splits the naive
// scheme://user:pass@host match) — from a realistic connect-error message.
test('errors/redactSensitive: strips Mongo connection-string credentials (incl. an @-containing password) from a raw connect-error message', () => {
  const { redactSensitive } = require('./lib/errors');
  const msg = 'MongoServerSelectionError: connect ETIMEDOUT mongodb+srv://user:P@ssw0rd@cluster.example.mongodb.net/db?retryWrites=true&w=majority';
  const redacted = redactSensitive(msg);
  assert.ok(!redacted.includes('P@ssw0rd'), 'the literal credential must not appear in the redacted message');
  assert.ok(!redacted.includes('user:P@ssw0rd@cluster'), 'the full user:pass@host must not survive redaction');
  assert.ok(!redacted.includes('ssw0rd'), 'no fragment of the password may leak either');
});

// Both top-level catches must actually call redactSensitive (not just that
// redactSensitive itself works) — read the source and assert the wiring.
test('cli.js/server.js: the top-level main().catch handlers wrap err.message in redactSensitive before logging', () => {
  const fs = require('fs');
  const path = require('path');
  const cliSrc = fs.readFileSync(path.join(__dirname, 'cli.js'), 'utf8');
  const serverSrc = fs.readFileSync(path.join(__dirname, 'server.js'), 'utf8');
  assert.match(cliSrc, /require\(['"]\.\/lib\/errors['"]\)/, 'cli.js must import redactSensitive from ./lib/errors');
  const cliCatch = cliSrc.slice(cliSrc.indexOf('if (require.main === module)'));
  assert.match(cliCatch, /console\.error\(\s*redactSensitive\(/, 'cli.js top-level catch must redact before logging');
  const serverCatches = serverSrc.slice(serverSrc.indexOf('const onSignal'));
  assert.match(serverCatches, /console\.error\(\s*redactSensitive\(/, 'server.js shutdown-signal catch must redact before logging');
  const serverTopCatch = serverSrc.slice(serverSrc.indexOf('if (require.main === module)'));
  assert.match(serverTopCatch, /console\.error\(\s*redactSensitive\(/, 'server.js top-level catch must redact before logging');
});

// ===========================================================================
// REVIEW FIX #2 — OTP attempt cap is atomic under concurrency
// ===========================================================================

test('otp/fix: concurrent wrong-code verifies cannot exceed the attempt cap', async () => {
  const ctx = makeCtx();
  const su = await signup.signup(ctx, { email: 'race@superworks.com', password: 'password12345' });
  await otp.issueOtp(ctx, { userId: su.userId, purpose: 'signup', email: 'race@superworks.com' });
  const max = ctx.config.otp.maxAttempts;
  // Fire many concurrent wrong guesses.
  const results = await Promise.allSettled(
    Array.from({ length: max + 8 }, () => signup.verifySignup(ctx, { email: 'race@superworks.com', code: '000001' })),
  );
  const statuses = results.map(r => (r.status === 'rejected' ? r.reason.status : 'ok'));
  const rejected400 = statuses.filter(s => s === 400).length;
  const locked429 = statuses.filter(s => s === 429).length;
  // Exactly `max` guesses reached the compare (400); the rest were capped (429).
  assert.equal(rejected400, max, `exactly ${max} guesses should be tested`);
  assert.equal(locked429, 8);
  const [stored] = await ctx.repo.otps.find({});
  assert.equal(stored.attempts, max, 'attempts counter must stop exactly at the cap');
});

// ===========================================================================
// REVIEW FIX #4/#7 — audit head-truncation detection via signed anchors
// ===========================================================================

test('audit/fix: deleting events below a higher signed anchor is detected (head-truncation)', async () => {
  const ctx = makeCtx();
  await recordSome(ctx, 5);
  await audit.anchorNow(ctx); // signed anchor @ seqHigh=5
  const anchors = await ctx.repo.auditAnchors.find({});
  const events = await ctx.repo.auditEvents.find({});
  const truncated = events.filter(e => e.seq <= 3); // attacker deletes 4,5
  const res = audit.verifyEvents(truncated, anchors, {
    hmacKey: ctx.config.auditHmacKey, anchorPublicKey: ctx.config.anchorPublicKey,
  });
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'anchor_ahead_of_head');
});

test('audit/fix: wiping ALL events while a signed anchor exists is detected', async () => {
  const ctx = makeCtx();
  await recordSome(ctx, 3);
  await audit.anchorNow(ctx);
  const anchors = await ctx.repo.auditAnchors.find({});
  const res = audit.verifyEvents([], anchors, {
    hmacKey: ctx.config.auditHmacKey, anchorPublicKey: ctx.config.anchorPublicKey,
  });
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'anchor_ahead_of_head');
});

test('audit/fix: an intact chain with a matching head anchor still verifies', async () => {
  const ctx = makeCtx();
  await recordSome(ctx, 4);
  await audit.anchorNow(ctx); // anchor @ 4 == head
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true);
});

// ===========================================================================
// REVIEW FIX #13 — hash-chain domain separation across ledgers
// ===========================================================================

test('chain/fix: audit rows cannot be transplanted into the permission_changes chain', async () => {
  const ctx = makeCtx();
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'u1' });
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'u2' });
  const auditRows = await ctx.repo.auditEvents.find({});
  // Valid as an audit chain...
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true);
  // ...but rejected when verified under the permission_changes domain, so an
  // attacker with DB write access cannot pass the perm-ledger tamper check by
  // copying legitimately-signed audit rows into it.
  assert.equal(hashchain.verifyChain(auditRows, ctx.config.auditHmacKey, { domain: 'permission_changes' }).ok, false);
  assert.equal(hashchain.verifyChain(auditRows, ctx.config.auditHmacKey, { domain: 'audit_events' }).ok, true);
});

// ===========================================================================
// REVIEW FIX #5/#14/#26 — entitlement input validation + safe ordering
// ===========================================================================

test('entitlements/fix: invalid expiry date is rejected (400), user unchanged, nothing recorded', async () => {
  const ctx = makeCtx();
  const adm = await makeActiveUser(ctx, { email: 'a4@superworks.com', password: 'password12345', role: 'admin' });
  const m = await makeActiveUser(ctx, { email: 'm4@superworks.com', password: 'password12345' });
  await assert.rejects(
    () => entitlements.setEntitlement(ctx, { adminId: adm._id, targetUserId: m._id, field: 'entitlementExpiresAt', value: '2026-13-45' }),
    (e) => e.status === 400,
  );
  const after = await ctx.repo.users.findById(m._id);
  assert.equal(after.entitlementExpiresAt, null, 'no invalid date persisted (no fail-open)');
  assert.equal((await ctx.repo.permissionChanges.find({})).length, 0, 'no ledger entry for a rejected change');
});

test('entitlements/fix: invalid status is rejected (400)', async () => {
  const ctx = makeCtx();
  const adm = await makeActiveUser(ctx, { email: 'a5@superworks.com', password: 'password12345', role: 'admin' });
  const m = await makeActiveUser(ctx, { email: 'm5@superworks.com', password: 'password12345' });
  await assert.rejects(
    () => entitlements.setEntitlement(ctx, { adminId: adm._id, targetUserId: m._id, field: 'status', value: 'Actve' }),
    (e) => e.status === 400,
  );
  assert.equal((await ctx.repo.users.findById(m._id)).status, 'active', 'status not corrupted by typo');
});

test('entitlements/fix: an unparseable stored expiry fails CLOSED (treated as expired)', async () => {
  const ctx = makeCtx();
  const m = await makeActiveUser(ctx, { email: 'm6@superworks.com', password: 'password12345' });
  // Simulate a legacy/corrupt record written before validation existed.
  await ctx.repo.users.updateById(m._id, { importEnabled: true, entitlementExpiresAt: new Date('nonsense') });
  const ent = await entitlements.getLiveEntitlements(ctx, m._id);
  assert.equal(ent.expired, true);
  assert.equal(ent.importEnabled, false, 'invalid expiry must not grant a permanent entitlement');
});

// ===========================================================================
// REVIEW FIX #6/#15/#16 — XFF trust, event-type whitelist, per-user idempotency
// ===========================================================================

test('reqsec/fix: X-Forwarded-For is ignored unless trustProxy (no rate-limit-bucket spoofing)', () => {
  const headers = { 'x-forwarded-for': '10.0.0.9' };
  // Default (untrusted): the client-supplied XFF is ignored → socket peer used.
  assert.equal(resolveClientIp(headers, '203.0.113.5', false), '203.0.113.5');
  // Behind a configured proxy: the forwarded client IP is honored.
  assert.equal(resolveClientIp(headers, '203.0.113.5', true), '10.0.0.9');
});

test('reqsec/fix: audit ingestion rejects privileged/server-only event types (400)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'forge@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'forge@superworks.com', 'password12345', 'dev-f');
  for (const evt of ['remote_wipe', 'admin_grant', 'anomaly', 'remote_lock', 'admin_revoke']) {
    const r = await routes.handleRequest(ctx, req('POST', '/audit/events', { headers: { authorization: bearer }, body: { eventType: evt } }));
    assert.equal(r.status, 400, `${evt} must be rejected`);
  }
  assert.equal((await ctx.repo.auditEvents.find({})).length, 0, 'no forged privileged events written');
});

test('reqsec/fix: idempotency key is per-user — one user cannot suppress another', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'ua@superworks.com', password: 'password12345' });
  await makeActiveUser(ctx, { email: 'ub@superworks.com', password: 'password12345' });
  const ba = await bearerFor(ctx, 'ua@superworks.com', 'password12345', 'da');
  const bb = await bearerFor(ctx, 'ub@superworks.com', 'password12345', 'db');
  const body = { eventType: 'switch' };
  const r1 = await routes.handleRequest(ctx, req('POST', '/audit/events', { headers: { authorization: ba, 'idempotency-key': 'k' }, body }));
  const r2 = await routes.handleRequest(ctx, req('POST', '/audit/events', { headers: { authorization: bb, 'idempotency-key': 'k' }, body }));
  assert.equal(r1.body.idempotent, false);
  assert.equal(r2.body.idempotent, false, 'user B reusing the same key must NOT be suppressed');
  assert.equal((await ctx.repo.auditEvents.find({})).length, 2, 'both users get their own event');
  assert.notEqual(r1.body.seq, r2.body.seq);
});

// ===========================================================================
// REVIEW FIX #12/#20/#25 — trailing-dot bypass, MX A-fallback, dup-key→409
// ===========================================================================

test('signup/fix: trailing-dot FQDN cannot bypass the disposable blocklist', async () => {
  const ctx = makeCtx();
  assert.equal(normalizeEmail('user@Mailinator.com.'), 'user@mailinator.com');
  assert.equal(isDisposableDomain('mailinator.com.'), true);
  await assert.rejects(
    () => signup.signup(ctx, { email: 'throwaway@mailinator.com.', password: 'password12345' }),
    (e) => e.status === 422,
  );
});

test('signup/fix: a domain with only an A record (no MX) is deliverable', async () => {
  const ctx = makeCtx({ resolveMx: async () => [], resolveHost: async () => ['203.0.113.10'] });
  const res = await signup.signup(ctx, { email: 'user@a-only.example', password: 'password12345' });
  assert.equal(res.status, 'pending');
});

test('signup/fix: no MX and no A record is still rejected (422)', async () => {
  const ctx = makeCtx({ resolveMx: async () => [], resolveHost: async () => [] });
  await assert.rejects(
    () => signup.signup(ctx, { email: 'user@dead.example', password: 'password12345' }),
    (e) => e.status === 422,
  );
});

test('signup/fix: concurrent signups for the same email → one succeeds, one 409 (no dup, no 500)', async () => {
  const ctx = makeCtx();
  const results = await Promise.allSettled([
    signup.signup(ctx, { email: 'duprace@superworks.com', password: 'password12345' }),
    signup.signup(ctx, { email: 'DupRace@superworks.com', password: 'password12345' }),
  ]);
  const ok = results.filter(r => r.status === 'fulfilled');
  const failed = results.filter(r => r.status === 'rejected');
  assert.equal(ok.length, 1);
  assert.equal(failed.length, 1);
  assert.equal(failed[0].reason.status, 409, 'unique-index race maps to 409, not 500');
  assert.equal((await ctx.repo.users.find({})).length, 1, 'exactly one user created');
});

// ###########################################################################
// PHASE 2 — Backend control plane
// ###########################################################################

// ===========================================================================
// P2 STEP 0 — netip: canonicalization, CIDR matching, record-bound IP crypto
// ===========================================================================

test('netip: canonicalizeIp folds IPv4-mapped IPv6, case, and bracket+port to one form', () => {
  assert.equal(netip.canonicalizeIp('1.2.3.4'), '1.2.3.4');
  assert.equal(netip.canonicalizeIp('::ffff:1.2.3.4'), '1.2.3.4', 'mapped v6 → dotted v4');
  assert.equal(netip.canonicalizeIp('::FFFF:1.2.3.4'), '1.2.3.4', 'mapped v6 case-insensitive');
  assert.equal(netip.canonicalizeIp('0:0:0:0:0:ffff:1.2.3.4'), '1.2.3.4', 'expanded mapped form folds too');
  assert.equal(netip.canonicalizeIp('2001:DB8::1'), netip.canonicalizeIp('2001:db8:0:0:0:0:0:1'), 'v6 case + zero-compression unify');
  assert.equal(netip.canonicalizeIp('[2001:db8::1]:443'), '2001:db8::1', 'bracket+port stripped');
  assert.equal(netip.canonicalizeIp('1.2.3.4:5678'), '1.2.3.4', 'ipv4:port stripped');
  assert.equal(netip.canonicalizeIp('  1.2.3.4  '), '1.2.3.4', 'trimmed');
  assert.equal(netip.canonicalizeIp(''), '');
  assert.equal(netip.canonicalizeIp(null), '');
});

test('netip: ipIdx is identical across textual encodings of the same address (equality search)', () => {
  const ctx = makeCtx();
  assert.equal(netip.ipIdxOf(ctx, '::ffff:203.0.113.5'), netip.ipIdxOf(ctx, '203.0.113.5'),
    'mapped-v6 and dotted-v4 of one host must share an ipIdx or block/trace matching breaks');
  assert.equal(netip.ipIdxOf(ctx, '2001:DB8::1'), netip.ipIdxOf(ctx, '2001:db8:0:0:0:0:0:1'));
  assert.notEqual(netip.ipIdxOf(ctx, '1.2.3.4'), netip.ipIdxOf(ctx, '1.2.3.5'));
  assert.equal(netip.ipIdxOf(ctx, ''), null);
});

test('netip: ipInCidr matches v4 ranges, host routes, /0, and boundaries', () => {
  assert.equal(netip.ipInCidr('10.0.0.5', '10.0.0.0/24'), true);
  assert.equal(netip.ipInCidr('10.0.1.5', '10.0.0.0/24'), false);
  assert.equal(netip.ipInCidr('10.0.0.0', '10.0.0.0/24'), true, 'network address in range');
  assert.equal(netip.ipInCidr('10.0.0.255', '10.0.0.0/24'), true, 'broadcast address in range');
  assert.equal(netip.ipInCidr('1.2.3.4', '1.2.3.4'), true, 'bare addr = /32 host route');
  assert.equal(netip.ipInCidr('1.2.3.4', '1.2.3.4/32'), true);
  assert.equal(netip.ipInCidr('1.2.3.5', '1.2.3.4/32'), false);
  assert.equal(netip.ipInCidr('9.9.9.9', '0.0.0.0/0'), true, '/0 matches everything');
});

test('netip: ipInCidr treats IPv4-mapped IPv6 as the v4 address (no block bypass)', () => {
  // The classic bypass: a rule on 1.2.3.4/32 must still match a connection that
  // arrives as ::ffff:1.2.3.4 behind a dual-stack proxy.
  assert.equal(netip.ipInCidr('::ffff:1.2.3.4', '1.2.3.4/32'), true);
  assert.equal(netip.ipInCidr('1.2.3.4', '::ffff:1.2.3.4'), true, 'mapped host route folds to the v4 /32');
});

test('netip: ipInCidr v6 ranges + cross-family returns false, never throws', () => {
  assert.equal(netip.ipInCidr('2001:db8::1', '2001:db8::/32'), true);
  assert.equal(netip.ipInCidr('2001:db9::1', '2001:db8::/32'), false);
  assert.equal(netip.ipInCidr('2001:db8::1', '2001:db8::1/128'), true);
  // A v4 address against a (non-mapped) v6 rule is simply no-match, not a crash.
  assert.equal(netip.ipInCidr('1.2.3.4', '2001:db8::/32'), false);
  assert.equal(netip.ipInCidr('2001:db8::1', '10.0.0.0/8'), false);
  // Malformed input is a safe no-match (never 500s the pipeline).
  assert.equal(netip.ipInCidr('not-an-ip', '10.0.0.0/8'), false);
  assert.equal(netip.ipInCidr('10.0.0.1', 'garbage/99'), false);
});

test('netip: isValidCidr accepts sane rules and rejects junk', () => {
  assert.equal(netip.isValidCidr('10.0.0.0/8'), true);
  assert.equal(netip.isValidCidr('2001:db8::/32'), true);
  assert.equal(netip.isValidCidr('1.2.3.4'), true);
  assert.equal(netip.isValidCidr('10.0.0.0/33'), false, 'v4 prefix > 32');
  assert.equal(netip.isValidCidr('2001:db8::/129'), false, 'v6 prefix > 128');
  assert.equal(netip.isValidCidr('not-an-ip/24'), false);
  assert.equal(netip.isValidCidr(''), false);
});

test('netip: encryptIp round-trips with record-bound AAD and canonicalizes first', () => {
  const ctx = makeCtx();
  const { ipEnc, ipIdx } = netip.encryptIp(ctx, '::ffff:203.0.113.9', 'device-abc');
  assert.ok(ipEnc && ipIdx);
  assert.equal(netip.decryptIp(ctx, ipEnc, 'device-abc'), '203.0.113.9', 'decrypts to the canonical form');
  // Record binding: the same ciphertext cannot be relocated to another record.
  assert.throws(() => netip.decryptIp(ctx, ipEnc, 'device-XYZ'), 'wrong record AAD must fail auth');
  // ipIdx matches the canonical form regardless of the record context.
  assert.equal(ipIdx, netip.ipIdxOf(ctx, '203.0.113.9'));
});

test('netip: empty/missing IP yields null enc+idx (never encrypt(""))', () => {
  const ctx = makeCtx();
  assert.deepEqual(netip.encryptIp(ctx, '', 'dev'), { ipEnc: null, ipIdx: null });
  assert.deepEqual(netip.encryptIp(ctx, null, 'dev'), { ipEnc: null, ipIdx: null });
  assert.equal(netip.decryptIp(ctx, null, 'dev'), null);
});

test('config: Phase 2 tunables load with safe defaults', () => {
  const cfg = loadConfig(fullEnv());
  assert.equal(cfg.trustedProxyHops, 1);
  assert.equal(cfg.retentionDays, 7);
  assert.equal(cfg.refreshAbsoluteLifetimeMs, 90 * 24 * 60 * 60 * 1000);
  assert.ok(cfg.anchorIntervalMs > 0 && cfg.pruneIntervalMs > 0);
  assert.equal(cfg.anomaly.impossibleTravelKmh, 900);
  assert.equal(cfg.anomaly.deadManDays, 7);
  // Overridable via env.
  assert.equal(loadConfig(fullEnv({ RETENTION_DAYS: '3', TRUSTED_PROXY_HOPS: '2' })).retentionDays, 3);
  assert.equal(loadConfig(fullEnv({ TRUSTED_PROXY_HOPS: '2' })).trustedProxyHops, 2);
});

test('repo: Phase 2 collections exist with the expected surface', () => {
  const repo = createMemoryRepo();
  for (const name of ['permAnchors', 'ipRules', 'watermarks', 'watermarkImports', 'commands', 'loginAttempts']) {
    assert.equal(typeof repo[name].insert, 'function', `${name} is a collection`);
    assert.equal(typeof repo[name].find, 'function');
  }
  assert.equal(typeof repo.stats, 'function');
});

test('repo/append-only: deleteBelowSeq prunes a prefix, keeps the head, never lowers headSeq', async () => {
  const repo = createMemoryRepo();
  for (let i = 1; i <= 6; i++) await repo.auditEvents.insert({ seq: i, prevHash: 'p', entryHash: 'h' + i });
  // Prune everything at/below seq 4 → 5,6 remain.
  const deleted = await repo.auditEvents.deleteBelowSeq(4);
  assert.equal(deleted, 4);
  assert.deepEqual((await repo.auditEvents.find({})).map(e => e.seq), [5, 6]);
  // Head is intact and the next insert continues at head.seq+1 (no seq reuse).
  const head = await repo.auditEvents.getHead();
  assert.equal(head.seq, 6);
  await repo.auditEvents.insert({ seq: 7, prevHash: head.entryHash, entryHash: 'h7' });
  assert.equal((await repo.auditEvents.getHead()).seq, 7);
});

test('repo/append-only: deleteBelowSeq refuses to delete the head even if boundary >= headSeq', async () => {
  const repo = createMemoryRepo();
  for (let i = 1; i <= 3; i++) await repo.auditEvents.insert({ seq: i, prevHash: 'p', entryHash: 'h' + i });
  const deleted = await repo.auditEvents.deleteBelowSeq(99); // absurd boundary
  assert.equal(deleted, 2, 'head is never removed');
  assert.deepEqual((await repo.auditEvents.find({})).map(e => e.seq), [3]);
  assert.equal((await repo.auditEvents.getHead()).seq, 3);
});

test('repo: stats() returns a byte estimate that grows with data', async () => {
  const repo = createMemoryRepo();
  const empty = (await repo.stats()).estimatedBytes;
  await repo.users.insert({ email: 'a@b.c', blob: 'x'.repeat(500) });
  const filled = (await repo.stats()).estimatedBytes;
  assert.ok(filled > empty, 'stored data increases the estimate');
  assert.equal(typeof filled, 'number');
});

// ===========================================================================
// P2 HARDENING — #11 absolute refresh lifetime, #17/#19 login timing
// ===========================================================================

test('auth/fix #11: a refresh family cannot outlive the absolute-lifetime cap', async () => {
  const ctx = makeCtx();
  ctx.config = { ...ctx.config, refreshAbsoluteLifetimeMs: 60_000 }; // 1-min cap for the test
  await makeActiveUser(ctx, { email: 'abs@superworks.com', password: 'password12345' });
  const s1 = await auth.login(ctx, { email: 'abs@superworks.com', password: 'password12345', deviceId: 'dev-1' });
  // Rotations keep working within the cap...
  const s2 = await auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-1' });
  ctx.clock.advance(61_000); // now past the absolute cap
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s2.refreshToken, deviceId: 'dev-1' }), (e) => e.status === 401);
  // Fresh login mints a new family with a new start, so it works again.
  const s3 = await auth.login(ctx, { email: 'abs@superworks.com', password: 'password12345', deviceId: 'dev-1' });
  assert.ok(s3.accessToken);
});

test('auth/fix #11: the absolute cap hard-revokes even during the benign-retry grace window', async () => {
  const ctx = makeCtx();
  ctx.config = { ...ctx.config, refreshAbsoluteLifetimeMs: 5_000, refreshGraceMs: 60_000 }; // cap < grace
  await makeActiveUser(ctx, { email: 'absg@superworks.com', password: 'password12345' });
  const s1 = await auth.login(ctx, { email: 'absg@superworks.com', password: 'password12345', deviceId: 'dev-1' });
  await auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-1' }); // rotate s1 → revoked at t0
  ctx.clock.advance(6_000); // past the 5s cap but well within the 60s grace window
  // Re-presenting s1 would normally be a benign 409 retry; the absolute cap check
  // runs FIRST and hard-revokes the family instead.
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-1' }), (e) => e.status === 401);
});

test('auth/fix #17/#19: the locked-account branch burns scrypt (no fast-path timing oracle)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'lockt@superworks.com', password: 'password12345' });
  for (let i = 0; i < 5; i++) {
    await auth.login(ctx, { email: 'lockt@superworks.com', password: 'bad', deviceId: 'd' }).catch(() => {});
  }
  // Time the locked-account path vs the unknown-email path; both must run one
  // scrypt, so the locked path is not a microsecond fast return.
  const t0 = process.hrtime.bigint();
  await auth.login(ctx, { email: 'lockt@superworks.com', password: 'password12345', deviceId: 'd' }).catch(() => {});
  const lockedNs = Number(process.hrtime.bigint() - t0);
  const t1 = process.hrtime.bigint();
  await auth.login(ctx, { email: 'ghost@superworks.com', password: 'whatever', deviceId: 'd' }).catch(() => {});
  const unknownNs = Number(process.hrtime.bigint() - t1);
  assert.ok(lockedNs > unknownNs * 0.4,
    `locked path (${lockedNs}ns) must be comparable to the unknown-email path (${unknownNs}ns), not a fast return`);
});

// ===========================================================================
// P2 STEP 1 — real client-IP resolution (hop selection, fail-closed)
// ===========================================================================

test('reqsec: XFF hop selection picks the rightmost genuine entry, ignores spoofed leftmost', () => {
  // Behind ONE trusted proxy that appends: the client can prepend junk, but the
  // proxy-appended (rightmost) entry is the genuine client IP.
  const h = { 'x-forwarded-for': '1.1.1.1, 203.0.113.9' }; // "spoof, realClient"
  assert.equal(resolveClientIp(h, 'proxyIP', true, 1), '203.0.113.9');
  // Two appending proxies: client = 3rd from the... = xff[len-hops].
  const h2 = { 'x-forwarded-for': 'spoof, 203.0.113.9, edgeProxy' };
  assert.equal(resolveClientIp(h2, 'proxyIP', true, 2), '203.0.113.9');
  // Single-entry XFF with the default single hop (backward compatible).
  assert.equal(resolveClientIp({ 'x-forwarded-for': '10.0.0.9' }, 'sock', true), '10.0.0.9');
});

test('reqsec: XFF shorter than the hop count FAILS CLOSED to the socket peer (no leftmost spoof)', () => {
  // hops=2 but only one entry present → cannot trust it; must NOT return the
  // client-controlled leftmost entry. Falls back to the socket peer.
  const h = { 'x-forwarded-for': '1.2.3.4' };
  assert.equal(resolveClientIp(h, '198.51.100.7', true, 2), '198.51.100.7');
  // No XFF at all → socket peer.
  assert.equal(resolveClientIp({}, '198.51.100.7', true, 1), '198.51.100.7');
  // trustProxy off → always socket peer regardless of XFF.
  assert.equal(resolveClientIp({ 'x-forwarded-for': '9.9.9.9' }, '198.51.100.7', false, 1), '198.51.100.7');
});

// ===========================================================================
// P2 STEP 1/2 — server-stamped IP + coarse geo enrichment on audit events
// ===========================================================================

test('audit/enrich: recordEvent server-stamps record-bound ipEnc/ipIdx; no plaintext IP stored', async () => {
  const ctx = makeCtx();
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'u1', ip: '::ffff:203.0.113.42' });
  const [e] = await ctx.repo.auditEvents.find({});
  assert.ok(e.ipEnc && e.ipIdx, 'ipEnc + ipIdx are stamped');
  // ipEnc is AAD-bound to the event userId and decrypts to the canonical IP.
  assert.equal(netip.decryptIp(ctx, e.ipEnc, 'u1'), '203.0.113.42');
  // ipIdx enables equality search against the canonical form.
  assert.equal(e.ipIdx, netip.ipIdxOf(ctx, '203.0.113.42'));
  // No plaintext IP anywhere on the record, and the raw `ip` never entered core.
  const blob = JSON.stringify(e);
  assert.ok(!blob.includes('203.0.113.42'));
  assert.equal(e.ip, undefined);
});

test('audit/enrich: client-supplied ipEnc/ipIdx/geo are STRIPPED and replaced by server values', async () => {
  const ctx = makeCtx({ geo: fakeGeo({ country: 'US', region: 'CA', city: 'SF', asn: 'AS15169' }) });
  await audit.recordEvent(ctx, {
    eventType: 'login', userId: 'u1', ip: '8.8.8.8',
    geo: { country: 'ZZ', city: 'Faketown' },      // attacker-supplied
    ipEnc: 'forged-blob', ipIdx: 'forged-idx',      // attacker-supplied
  });
  const [e] = await ctx.repo.auditEvents.find({});
  assert.equal(e.geo.country, 'US', 'server geo wins, not the client-supplied ZZ');
  assert.notEqual(e.ipEnc, 'forged-blob');
  assert.notEqual(e.ipIdx, 'forged-idx');
  assert.equal(netip.decryptIp(ctx, e.ipEnc, 'u1'), '8.8.8.8');
});

test('audit/enrich: geo is coarse only — lat/lon are NEVER persisted', async () => {
  const ctx = makeCtx({ geo: fakeGeo({ country: 'us', region: 'CA', city: 'SF', asn: 'AS1', lat: 37.77, lon: -122.41 }) });
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'u1', ip: '8.8.8.8' });
  const [e] = await ctx.repo.auditEvents.find({});
  assert.deepEqual(e.geo, { country: 'US', region: 'CA', city: 'SF', asn: 'AS1' });
  assert.equal(e.geo.lat, undefined);
  assert.equal(e.geo.lon, undefined);
});

test('audit/enrich: a geo provider that throws degrades to no-geo without failing the ingest', async () => {
  const throwingGeo = { async lookup() { throw new Error('provider down'); } };
  const ctx = makeCtx({ geo: throwingGeo });
  const r = await audit.recordEvent(ctx, { eventType: 'login', userId: 'u1', ip: '8.8.8.8' });
  assert.equal(r.seq, 1, 'ingest still succeeds');
  const [e] = await ctx.repo.auditEvents.find({});
  assert.equal(e.geo, undefined, 'no geo, but ipEnc still stamped');
  assert.ok(e.ipEnc);
});

// ===========================================================================
// P2 STEP 2 — geo resolver: private/invalid → null, coarse-only, haversine
// ===========================================================================

test('geo: resolver returns null for private/invalid IPs and on provider error', async () => {
  const provider = async () => ({ country: 'US' });
  const resolver = geo.createGeoResolver(provider);
  assert.equal(await resolver.lookup('10.0.0.5'), null, 'RFC1918 private → null');
  assert.equal(await resolver.lookup('127.0.0.1'), null, 'loopback → null');
  assert.equal(await resolver.lookup('::1'), null, 'v6 loopback → null');
  assert.equal(await resolver.lookup('not-an-ip'), null, 'junk → null');
  assert.deepEqual(await resolver.lookup('8.8.8.8'), { country: 'US' }, 'public IP → provider result');
  const boom = geo.createGeoResolver(async () => { throw new Error('x'); });
  assert.equal(await boom.lookup('8.8.8.8'), null, 'provider throw → null');
});

test('geo: coarseGeo strips lat/lon and uppercases country; haversineKm sanity', () => {
  assert.deepEqual(
    geo.coarseGeo({ country: 'gb', region: 'ENG', city: 'London', asn: 'AS5', lat: 51.5, lon: -0.1 }),
    { country: 'GB', region: 'ENG', city: 'London', asn: 'AS5' },
  );
  assert.equal(geo.coarseGeo(null), null);
  // London ↔ New York ≈ 5570 km.
  const d = geo.haversineKm({ lat: 51.5, lon: -0.1 }, { lat: 40.7, lon: -74.0 });
  assert.ok(d > 5000 && d < 6000, `expected ~5570km, got ${d}`);
  assert.equal(geo.haversineKm({ lat: 1, lon: 1 }, { lat: null, lon: 2 }), null, 'missing coord → null');
});

// ===========================================================================
// P2 STEP 3/4 — anomaly emit primitive, ip_rules, geo-fence, pipeline gates
// ===========================================================================

const anomaly = require('./lib/anomaly');
const access = require('./lib/access');
const presence = require('./lib/presence');

// A geo double that returns a per-IP record (for travel/geo tests).
function geoByIp(map) {
  return { async lookup(ip) { return map[netip.canonicalizeIp(ip)] || null; } };
}

test('anomaly/emit: records a server-authored anomaly event and emails admins once per incident', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const r1 = await anomaly.emit(ctx, { severity: 'critical', userId: 'u1', reason: 'impossible_travel', dedupeKey: 'k1' });
  assert.equal(r1.idempotent, false);
  const [e] = await ctx.repo.auditEvents.find({ eventType: 'anomaly' });
  assert.equal(e.severity, 'critical');
  assert.equal(e.reason, 'impossible_travel');
  assert.equal(ctx.mailer.sent.length, 1, 'one admin alert email');
  assert.ok(ctx.mailer.sent[0].to.includes('admin@superworks.com'));
  // Same dedupeKey → coalesced: no second ledger row, no second email.
  const r2 = await anomaly.emit(ctx, { severity: 'critical', userId: 'u1', reason: 'impossible_travel', dedupeKey: 'k1' });
  assert.equal(r2.idempotent, true);
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'anomaly' })).length, 1);
  assert.equal(ctx.mailer.sent.length, 1, 'no duplicate email for the same incident');
});

test('anomaly/emit: fails open — a throwing mailer or zero admins never throws into the caller', async () => {
  const boomMailer = { sent: [], async send() { throw new Error('smtp down'); } };
  const ctx = makeCtx({ mailer: boomMailer });
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  // Mailer throws, but emit swallows it and still records the event.
  const r = await anomaly.emit(ctx, { severity: 'warn', reason: 'new_device', dedupeKey: 'nd1' });
  assert.ok(r && r.idempotent === false);
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'anomaly' })).length, 1);
  // Zero admins → no recipient, no throw.
  const ctx2 = makeCtx();
  const r2 = await anomaly.emit(ctx2, { severity: 'warn', reason: 'new_device', dedupeKey: 'nd2' });
  assert.ok(r2);
  assert.equal(ctx2.mailer.sent.length, 0);
});

test('access/evalScope: block beats allow; allowlist mode denies non-members', () => {
  const rules = [
    { type: 'allow', cidr: '10.0.0.0/8' },
    { type: 'block', cidr: '10.0.0.5/32' },
  ];
  assert.deepEqual(access.evalScope(rules, '10.0.0.9'), { blocked: false, denyByAllowlist: false }, 'allowed member');
  assert.deepEqual(access.evalScope(rules, '10.0.0.5'), { blocked: true, denyByAllowlist: false }, 'block wins');
  assert.deepEqual(access.evalScope(rules, '203.0.113.1'), { blocked: false, denyByAllowlist: true }, 'not in allowlist');
  assert.deepEqual(access.evalScope([{ type: 'block', cidr: '1.2.3.0/24' }], '9.9.9.9'), { blocked: false, denyByAllowlist: false }, 'pure blocklist lets others through');
});

test('access/http: a globally-blocklisted IP is refused PRE-AUTH on login, with a server anomaly', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await makeActiveUser(ctx, { email: 'victim@superworks.com', password: 'password12345' });
  await access.addIpRule(ctx, { adminId: admin._id, scope: 'global', type: 'block', cidr: '9.9.9.0/24' });
  const res = await routes.handleRequest(ctx, req('POST', '/auth/login', {
    body: { email: 'victim@superworks.com', password: 'password12345', deviceId: 'd' }, ip: '9.9.9.9',
  }));
  assert.equal(res.status, 403, 'blocked before the password is ever checked');
  const anomalies = await ctx.repo.auditEvents.find({ eventType: 'anomaly' });
  assert.ok(anomalies.length >= 1 && anomalies[0].reason === 'ip_blocked');
  // A non-blocked IP still logs in fine.
  const ok = await routes.handleRequest(ctx, req('POST', '/auth/login', {
    body: { email: 'victim@superworks.com', password: 'password12345', deviceId: 'd' }, ip: '8.8.8.8',
  }));
  assert.equal(ok.status, 200);
});

test('access/http: a per-user block denies that user POST-AUTH but not others', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'd');
  await access.addIpRule(ctx, { adminId: admin._id, scope: 'user', userId: member._id, type: 'block', cidr: '5.5.5.5/32' });
  const denied = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '5.5.5.5' }));
  assert.equal(denied.status, 403);
  const allowed = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '6.6.6.6' }));
  assert.equal(allowed.status, 200, 'a different IP for the same user is fine');
});

test('access: deny anomalies coalesce — many rapid denials from one IP are one incident', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await ctx.repo.ipRules.insert({ scope: 'global', type: 'block', cidr: '9.9.9.0/24', createdAt: ctx.clock.now() });
  for (let i = 0; i < 4; i++) {
    await routes.handleRequest(ctx, req('GET', '/health', { ip: '9.9.9.9' }));
  }
  const anomalies = await ctx.repo.auditEvents.find({ eventType: 'anomaly' });
  assert.equal(anomalies.length, 1, 'repeated denials from one IP coalesce to a single incident');
  assert.equal(ctx.mailer.sent.length, 1);
});

test('access/admin: ip-rule CRUD is admin-gated, recorded in permission_changes, and validated', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  // Non-admin refused.
  await assert.rejects(
    () => access.addIpRule(ctx, { adminId: member._id, scope: 'global', type: 'block', cidr: '1.2.3.0/24' }),
    (e) => e.status === 403,
  );
  // Invalid CIDR + bad scope/userId combos → 400.
  await assert.rejects(() => access.addIpRule(ctx, { adminId: admin._id, scope: 'global', type: 'block', cidr: 'not-a-cidr' }), (e) => e.status === 400);
  await assert.rejects(() => access.addIpRule(ctx, { adminId: admin._id, scope: 'user', type: 'block', cidr: '1.2.3.0/24' }), (e) => e.status === 400);
  await assert.rejects(() => access.addIpRule(ctx, { adminId: admin._id, scope: 'global', userId: member._id, type: 'block', cidr: '1.2.3.0/24' }), (e) => e.status === 400);
  // Self-lockout guard: refuse a global block matching the admin's current IP.
  await assert.rejects(
    () => access.addIpRule(ctx, { adminId: admin._id, scope: 'global', type: 'block', cidr: '4.4.4.0/24', currentIp: '4.4.4.4' }),
    (e) => e.status === 400,
  );
  // Valid add → recorded + listable + removable.
  const rule = await access.addIpRule(ctx, { adminId: admin._id, scope: 'global', type: 'block', cidr: '1.2.3.0/24', reason: 'abuse' });
  assert.ok(rule._id);
  assert.equal((await access.listIpRules(ctx, { adminId: admin._id })).length, 1);
  const perm = await ctx.repo.permissionChanges.find({ field: 'ip_rule_add' });
  assert.equal(perm.length, 1);
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
  await access.removeIpRule(ctx, { adminId: admin._id, ruleId: rule._id });
  assert.equal((await access.listIpRules(ctx, { adminId: admin._id })).length, 0);
  assert.equal((await ctx.repo.permissionChanges.find({ field: 'ip_rule_remove' })).length, 1);
});

test('geofence/http: out-of-fence country is denied, in-fence allowed, null geo fails closed', async () => {
  // In-fence: fence=[US], geo=US → allowed.
  const ctxUS = makeCtx({ geo: fakeGeo({ country: 'US' }) });
  const adm = await makeActiveUser(ctxUS, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctxUS, { email: 'm@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctxUS, 'm@superworks.com', 'password12345', 'd');
  await access.setGeoFence(ctxUS, { adminId: adm._id, targetUserId: member._id, countries: ['us'] }); // lowercase normalizes
  const inFence = await routes.handleRequest(ctxUS, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(inFence.status, 200, 'US user within a US fence is allowed');
  // Out-of-fence: change fence to GB.
  await access.setGeoFence(ctxUS, { adminId: adm._id, targetUserId: member._id, countries: ['GB'] });
  const outFence = await routes.handleRequest(ctxUS, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(outFence.status, 403, 'US user outside a GB fence is denied');
  assert.ok((await ctxUS.repo.auditEvents.find({ eventType: 'anomaly', reason: 'geo_fenced' })).length >= 1);

  // Null geo under an active fence → fail closed.
  const ctxNull = makeCtx(); // null geo resolver
  const adm2 = await makeActiveUser(ctxNull, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const m2 = await makeActiveUser(ctxNull, { email: 'm2@superworks.com', password: 'password12345' });
  const bearer2 = await bearerFor(ctxNull, 'm2@superworks.com', 'password12345', 'd');
  await access.setGeoFence(ctxNull, { adminId: adm2._id, targetUserId: m2._id, countries: ['US'] });
  const noGeo = await routes.handleRequest(ctxNull, req('GET', '/entitlements/me', { headers: { authorization: bearer2 }, ip: '8.8.8.8' }));
  assert.equal(noGeo.status, 403, 'unverifiable location under a fence fails closed');
});

test('geofence/admin: invalid country codes are rejected (400); clearing the fence works', async () => {
  const ctx = makeCtx();
  const adm = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const m = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  await assert.rejects(() => access.setGeoFence(ctx, { adminId: adm._id, targetUserId: m._id, countries: ['USA'] }), (e) => e.status === 400);
  await assert.rejects(() => access.setGeoFence(ctx, { adminId: adm._id, targetUserId: m._id, countries: 'US' }), (e) => e.status === 400);
  await access.setGeoFence(ctx, { adminId: adm._id, targetUserId: m._id, countries: ['US', 'gb'] });
  assert.deepEqual((await ctx.repo.users.findById(m._id)).geoFence, { countries: ['US', 'GB'] });
  await access.setGeoFence(ctx, { adminId: adm._id, targetUserId: m._id, countries: [] });
  assert.equal((await ctx.repo.users.findById(m._id)).geoFence, null, 'empty array clears the fence');
});

// GEO-1 (red-team, Important): resolveGeo/ctx.geo.lookup was called UNCONDITIONALLY
// for every authenticated request in routes.js handleRequest, even though the
// result is used ONLY by enforceGeoFence — which early-returns for a user with
// no active fence. Under GEO_PROVIDER=ip-api that hammers the free-tier ~45
// req/min cap for every request from every non-fenced user, and once exhausted,
// FENCED users then fail closed (403) because their genuine lookups start
// failing too. The fix confines the external geo lookup to users who actually
// carry an active geoFence; enforceUserIp (the per-user IP rules) still runs
// for everyone.
function countingGeo(record) {
  const state = { calls: 0 };
  const resolver = { async lookup() { state.calls++; return record; } };
  return { resolver, state };
}

test('routes/geo: the per-request geo lookup is skipped for a user with NO active geo-fence, and still runs (and is enforced) for a fenced user', async () => {
  const { resolver, state } = countingGeo({ country: 'US' });
  const ctx = makeCtx({ geo: resolver });
  const adm = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const noFence = await makeActiveUser(ctx, { email: 'nofence@superworks.com', password: 'password12345' });
  const fenced = await makeActiveUser(ctx, { email: 'fenced@superworks.com', password: 'password12345' });
  await access.setGeoFence(ctx, { adminId: adm._id, targetUserId: fenced._id, countries: ['US'] });

  const bearerNoFence = await bearerFor(ctx, 'nofence@superworks.com', 'password12345', 'd1');
  const bearerFenced = await bearerFor(ctx, 'fenced@superworks.com', 'password12345', 'd2');

  // login() itself triggers an unrelated geo lookup (presence.recordPresence's
  // impossible-travel check) — reset the counter so we isolate ONLY the
  // per-request gate in routes.js handleRequest, which is what this finding is
  // about.
  state.calls = 0;

  const r1 = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearerNoFence }, ip: '8.8.8.8' }));
  assert.equal(r1.status, 200);
  assert.equal(state.calls, 0, 'a user with no active geo-fence must not trigger an external geo lookup on every request');

  const r2 = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearerFenced }, ip: '8.8.8.8' }));
  assert.equal(r2.status, 200, 'a US user within a matching US fence is still allowed');
  assert.equal(state.calls, 1, 'a user WITH an active geo-fence still triggers (and enforces) the geo lookup');

  // A second request from the non-fenced user still does not touch geo.
  const r3 = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearerNoFence }, ip: '8.8.8.8' }));
  assert.equal(r3.status, 200);
  assert.equal(state.calls, 1, 'geo lookup count is unchanged by a further non-fenced request');
});

// ===========================================================================
// F2 — per-user country DENY-LIST (blockedCountries), additive alongside the
// existing allow-list geoFence. Block beats allow; FAILS OPEN on an unknown/
// unresolved country (contrast with the allow-fence's fail-CLOSED behavior
// proven above).
// ===========================================================================

test('access.setBlockedCountries: non-admin 403; invalid ISO 400; normalizes + dedupes; null/[] clears; permission_changes recorded + chain verifies', async () => {
  const ctx = makeCtx();
  const adm = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const m = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });

  await assert.rejects(
    () => access.setBlockedCountries(ctx, { adminId: m._id, targetUserId: m._id, countries: ['US'] }),
    (e) => e.status === 403,
  );
  await assert.rejects(() => access.setBlockedCountries(ctx, { adminId: adm._id, targetUserId: m._id, countries: ['USA'] }), (e) => e.status === 400);
  await assert.rejects(() => access.setBlockedCountries(ctx, { adminId: adm._id, targetUserId: m._id, countries: 'US' }), (e) => e.status === 400);

  await access.setBlockedCountries(ctx, { adminId: adm._id, targetUserId: m._id, countries: ['us', 'US', 'gb'] });
  assert.deepEqual((await ctx.repo.users.findById(m._id)).blockedCountries, { countries: ['US', 'GB'] });

  await access.setBlockedCountries(ctx, { adminId: adm._id, targetUserId: m._id, countries: [] });
  assert.equal((await ctx.repo.users.findById(m._id)).blockedCountries, null, 'empty array clears the block-list');

  await access.setBlockedCountries(ctx, { adminId: adm._id, targetUserId: m._id, countries: ['US'] });
  await access.setBlockedCountries(ctx, { adminId: adm._id, targetUserId: m._id, countries: null });
  assert.equal((await ctx.repo.users.findById(m._id)).blockedCountries, null, 'null clears the block-list');

  const changes = await ctx.repo.permissionChanges.find({ field: 'blockedCountries' });
  assert.ok(changes.length >= 3);
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
});

test('geoblock/http: a blacklisted country is denied with reason geo_blocked; a different country is allowed', async () => {
  const ctxUS = makeCtx({ geo: fakeGeo({ country: 'US' }) });
  const adm = await makeActiveUser(ctxUS, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctxUS, { email: 'm@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctxUS, 'm@superworks.com', 'password12345', 'd');

  await access.setBlockedCountries(ctxUS, { adminId: adm._id, targetUserId: member._id, countries: ['US'] });
  const blocked = await routes.handleRequest(ctxUS, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(blocked.status, 403);
  const anomalies = await ctxUS.repo.auditEvents.find({ eventType: 'anomaly', reason: 'geo_blocked' });
  assert.ok(anomalies.length >= 1);

  await access.setBlockedCountries(ctxUS, { adminId: adm._id, targetUserId: member._id, countries: ['GB'] });
  const allowed = await routes.handleRequest(ctxUS, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(allowed.status, 200, 'a US user is fine once the block-list no longer includes US');
});

test('geoblock: block beats allow — a country both allowed by the fence and blocked is still denied', async () => {
  const ctx = makeCtx({ geo: fakeGeo({ country: 'US' }) });
  const adm = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'd');

  await access.setGeoFence(ctx, { adminId: adm._id, targetUserId: member._id, countries: ['US', 'GB'] });
  await access.setBlockedCountries(ctx, { adminId: adm._id, targetUserId: member._id, countries: ['US'] });

  const res = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(res.status, 403, 'US is in the allow-fence AND on the block-list — block wins');
  const anomalies = await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'geo_blocked' });
  assert.ok(anomalies.length >= 1);
});

test('geoblock: fails OPEN on an unresolved/unknown country — contrast with the allow-fence, which fails closed', async () => {
  const ctx = makeCtx(); // null geo resolver — every lookup resolves to null
  const adm = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'd');

  await access.setBlockedCountries(ctx, { adminId: adm._id, targetUserId: member._id, countries: ['US'] });
  const res = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(res.status, 200, 'an unverifiable location does not match a block — fail open');
});

test('routes/geo: a user with ONLY blockedCountries (no allow-fence) still triggers the geo lookup (needGeo widening)', async () => {
  // Country resolves to GB (not on the block-list) so the request is ALLOWED
  // (200) — isolates the routes.js gating widening from audit.js's OWN
  // internal geo-enrichment lookup on a denial (a second, unrelated
  // ctx.geo.lookup call fired by anomaly.emit -> audit.recordEvent), mirroring
  // the pre-existing fence-only GEO-1 test's allowed-path convention above.
  const { resolver, state } = countingGeo({ country: 'GB' });
  const ctx = makeCtx({ geo: resolver });
  const adm = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const blockedOnly = await makeActiveUser(ctx, { email: 'blockonly@superworks.com', password: 'password12345' });
  await access.setBlockedCountries(ctx, { adminId: adm._id, targetUserId: blockedOnly._id, countries: ['US'] });
  const bearer = await bearerFor(ctx, 'blockonly@superworks.com', 'password12345', 'd1');

  state.calls = 0;
  const res = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(res.status, 200, 'GB does not match the US block-list — allowed');
  assert.equal(state.calls, 1, 'a block-only user (no allow-fence) still triggers the external geo lookup');
});

test('route/admin: POST /admin/blocked-countries — member 403, admin 200', async () => {
  const ctx = makeCtx();
  const adm = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', 'password12345', 'dev-a');
  const memberBearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'dev-m');

  const denied = await routes.handleRequest(ctx, req('POST', '/admin/blocked-countries', {
    headers: { authorization: memberBearer }, body: { targetUserId: member._id, countries: ['US'] },
  }));
  assert.equal(denied.status, 403);

  const ok = await routes.handleRequest(ctx, req('POST', '/admin/blocked-countries', {
    headers: { authorization: adminBearer }, body: { targetUserId: member._id, countries: ['US'] },
  }));
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body.blockedCountries, { countries: ['US'] });
});

// ===========================================================================
// P2 — export/import AUTHORIZE (server enforcement point) + watermark trace
// ===========================================================================

// Set up admin + an entitled member; returns bearers and ids.
async function transferFixture(ctx, { exportEnabled = false, importEnabled = false } = {}) {
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  if (exportEnabled) await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'exportEnabled', value: true });
  if (importEnabled) await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'importEnabled', value: true });
  const memberBearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'dev-m');
  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', 'password12345', 'dev-a');
  return { admin, member, memberBearer, adminBearer };
}

test('export/authorize: entitled member gets a watermark + export event; denied member gets 403 + anomaly', async () => {
  const ctx = makeCtx();
  const { member, memberBearer } = await transferFixture(ctx, { exportEnabled: true });
  const res = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: memberBearer, 'idempotency-key': 'exp-1' },
    body: { fileMeta: { name: 'a.json', sha256: 'sha-abc', size: 10 } }, ip: '8.8.8.8',
  }));
  assert.equal(res.status, 200);
  assert.ok(res.body.watermarkId);
  const ev = await ctx.repo.auditEvents.find({ eventType: 'export' });
  assert.equal(ev.length, 1);
  assert.equal(ev[0].watermarkId, res.body.watermarkId);
  assert.ok(await ctx.repo.watermarks.findById(res.body.watermarkId));

  // A non-entitled user is refused, with an export_denied event + anomaly.
  await entitlements.setEntitlement(ctx, { adminId: (await users.findUserByEmail(ctx, 'admin@superworks.com'))._id, targetUserId: member._id, field: 'exportEnabled', value: false });
  const denied = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: memberBearer }, body: {}, ip: '8.8.8.8',
  }));
  assert.equal(denied.status, 403);
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'export_denied' })).length, 1);
  assert.ok((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'export_not_entitled' })).length >= 1);
});

test('export/authorize: idempotent retry returns the same watermark, one event, no double quota charge', async () => {
  const ctx = makeCtx();
  const { member, memberBearer } = await transferFixture(ctx, { exportEnabled: true });
  await ctx.repo.users.updateById(member._id, { exportQuota: { maxPerDay: 5, used: 0, windowStart: ctx.clock.now() } });
  const mk = (k) => routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: memberBearer, 'idempotency-key': k }, body: { fileMeta: { sha256: 's' } }, ip: '8.8.8.8',
  }));
  const r1 = await mk('exp-K');
  const r2 = await mk('exp-K');
  assert.equal(r2.body.watermarkId, r1.body.watermarkId, 'same watermark on retry');
  assert.equal(r2.body.idempotent, true);
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'export' })).length, 1);
  assert.equal((await ctx.repo.watermarks.find({})).length, 1);
  assert.equal((await ctx.repo.users.findById(member._id)).exportQuota.used, 1, 'quota charged once, not twice');
});

test('export/authorize: daily quota (maxPerDay>0) is enforced', async () => {
  const ctx = makeCtx();
  const { member, memberBearer } = await transferFixture(ctx, { exportEnabled: true });
  await ctx.repo.users.updateById(member._id, { exportQuota: { maxPerDay: 2, used: 0, windowStart: ctx.clock.now() } });
  const mk = (k) => routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: memberBearer, 'idempotency-key': k }, body: { fileMeta: { sha256: 's' } }, ip: '8.8.8.8',
  }));
  assert.equal((await mk('e1')).status, 200);
  assert.equal((await mk('e2')).status, 200);
  assert.equal((await mk('e3')).status, 429, 'third export in the window is over quota');
});

test('import/authorize: entitled import records a server-stamped tracer row; trace joins export↔import (admin only)', async () => {
  const ctx = makeCtx();
  // Exporter mints a watermark.
  const { member: exporter, memberBearer: exporterBearer, admin, adminBearer } = await transferFixture(ctx, { exportEnabled: true });
  const exp = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: exporterBearer, 'idempotency-key': 'x1' }, body: { fileMeta: { sha256: 'file-1' } }, ip: '8.8.8.8',
  }));
  const watermarkId = exp.body.watermarkId;
  // A different, import-entitled member imports it.
  const importer = await makeActiveUser(ctx, { email: 'imp@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: importer._id, field: 'importEnabled', value: true });
  const importerBearer = await bearerFor(ctx, 'imp@superworks.com', 'password12345', 'dev-i');
  const imp = await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: importerBearer, 'idempotency-key': 'i1' },
    body: { watermarkId, userId: 'FORGED', fileMeta: { sha256: 'file-1' } }, ip: '7.7.7.7',
  }));
  assert.equal(imp.status, 200);
  const imps = await ctx.repo.watermarkImports.find({ watermarkId });
  assert.equal(imps.length, 1);
  assert.equal(imps[0].userId, importer._id, 'importer identity is server-stamped, not the forged body value');
  // Admin trace shows the join with the decrypted importer IP.
  const tr = await routes.handleRequest(ctx, req('GET', '/watermarks/trace', { headers: { authorization: adminBearer }, query: { watermarkId } }));
  assert.equal(tr.status, 200);
  assert.equal(tr.body.export.userId, exporter._id);
  assert.equal(tr.body.imports.length, 1);
  assert.equal(tr.body.imports[0].ip, '7.7.7.7', 'admin sees the decrypted import IP');
  // A member cannot trace (admin-gated).
  const memberTrace = await routes.handleRequest(ctx, req('GET', '/watermarks/trace', { headers: { authorization: importerBearer }, query: { watermarkId } }));
  assert.equal(memberTrace.status, 403);
  // Import dedup: a repeated import of the same (watermark,user,file) adds no row.
  await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: importerBearer, 'idempotency-key': 'i2' }, body: { watermarkId, fileMeta: { sha256: 'file-1' } }, ip: '7.7.7.7',
  }));
  assert.equal((await ctx.repo.watermarkImports.find({ watermarkId })).length, 1, 'duplicate import is deduped');
});

test('import/authorize: a non-entitled import is refused (403) with import_denied + anomaly', async () => {
  const ctx = makeCtx();
  const { memberBearer } = await transferFixture(ctx); // no import entitlement
  const res = await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: memberBearer }, body: { watermarkId: 'wm-x' }, ip: '7.7.7.7',
  }));
  assert.equal(res.status, 403);
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'import_denied' })).length, 1);
  assert.ok((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'import_not_entitled' })).length >= 1);
});

// ===========================================================================
// Cross-user import leak alert (Phase 5 Task 5) — alert, not block: an import
// entitled to a DIFFERENT user than the export's owner still succeeds, but
// fires one server-authored critical anomaly carrying the provenance.
// ===========================================================================

test('import/authorize: cross-user import fires a critical cross_user_import anomaly; import still succeeds', async () => {
  const ctx = makeCtx();
  const { member: exporter, memberBearer: exporterBearer, admin, adminBearer } = await transferFixture(ctx, { exportEnabled: true });
  const exp = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: exporterBearer, 'idempotency-key': 'cu-x1' }, body: { fileMeta: { sha256: 'file-cu' } }, ip: '8.8.8.8',
  }));
  const watermarkId = exp.body.watermarkId;
  const importer = await makeActiveUser(ctx, { email: 'cu-imp@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: importer._id, field: 'importEnabled', value: true });
  const importerBearer = await bearerFor(ctx, 'cu-imp@superworks.com', 'password12345', 'dev-cu');

  const imp = await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: importerBearer, 'idempotency-key': 'cu-i1' },
    body: { watermarkId, fileMeta: { sha256: 'file-cu' } }, ip: '7.7.7.7',
  }));
  assert.equal(imp.status, 200, 'the import itself still succeeds (alert, not block)');

  const anomalies = await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'cross_user_import' });
  assert.equal(anomalies.length, 1, 'exactly one anomaly is recorded');
  const a = anomalies[0];
  assert.equal(a.severity, 'critical');
  assert.equal(a.watermarkId, watermarkId);
  assert.equal(a.userId, importer._id, 'the importer identity, server-stamped');
  assert.equal(a.deviceId, 'dev-cu');
  assert.equal(a.exportUserId, exporter._id, "the exporter's identity is carried too");

  // Visible in the admin alerts feed (route-level; already severity-filtered).
  const feed = await routes.handleRequest(ctx, req('GET', '/admin/reports/alerts', { headers: { authorization: adminBearer } }));
  assert.equal(feed.status, 200);
  const alert = feed.body.alerts.find(x => x.reason === 'cross_user_import');
  assert.ok(alert, 'the cross-user import anomaly appears in the admin alerts feed');
  assert.equal(alert.severity, 'critical');
  assert.equal(alert.eventType, 'anomaly');
  assert.equal(alert.userId, importer._id);
  assert.equal(alert.deviceId, 'dev-cu');

  // Visible in the timeline too (which surfaces watermarkId).
  const timeline = await routes.handleRequest(ctx, req('GET', '/admin/reports/timeline', { headers: { authorization: adminBearer } }));
  assert.equal(timeline.status, 200);
  const tlEvent = timeline.body.events.find(x => x.reason === 'cross_user_import');
  assert.ok(tlEvent, 'the anomaly appears in the timeline');
  assert.equal(tlEvent.watermarkId, watermarkId);
});

test('import/authorize: same-user import fires no cross-user anomaly', async () => {
  const ctx = makeCtx();
  const { memberBearer } = await transferFixture(ctx, { exportEnabled: true, importEnabled: true });
  const exp = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: memberBearer, 'idempotency-key': 'su-x1' }, body: { fileMeta: { sha256: 'file-su' } }, ip: '8.8.8.8',
  }));
  const watermarkId = exp.body.watermarkId;

  const imp = await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: memberBearer, 'idempotency-key': 'su-i1' },
    body: { watermarkId, fileMeta: { sha256: 'file-su' } }, ip: '8.8.8.8',
  }));
  assert.equal(imp.status, 200);
  const anomalies = await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'cross_user_import' });
  assert.equal(anomalies.length, 0, 'the exporter re-importing their own export is not an anomaly');
});

test('import/authorize: a replayed cross-user import (same recorded import) does not duplicate the anomaly', async () => {
  const ctx = makeCtx();
  const { member: exporter, memberBearer: exporterBearer, admin } = await transferFixture(ctx, { exportEnabled: true });
  const exp = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: exporterBearer, 'idempotency-key': 'rp-x1' }, body: { fileMeta: { sha256: 'file-rp' } }, ip: '8.8.8.8',
  }));
  const watermarkId = exp.body.watermarkId;
  const importer = await makeActiveUser(ctx, { email: 'rp-imp@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: importer._id, field: 'importEnabled', value: true });
  const importerBearer = await bearerFor(ctx, 'rp-imp@superworks.com', 'password12345', 'dev-rp');

  const imp1 = await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: importerBearer, 'idempotency-key': 'rp-i1' },
    body: { watermarkId, fileMeta: { sha256: 'file-rp' } }, ip: '7.7.7.7',
  }));
  assert.equal(imp1.status, 200);

  // Replay #1: the EXACT SAME idempotency key — short-circuited before
  // recordImport is even reached.
  const imp2 = await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: importerBearer, 'idempotency-key': 'rp-i1' },
    body: { watermarkId, fileMeta: { sha256: 'file-rp' } }, ip: '7.7.7.7',
  }));
  assert.equal(imp2.status, 200);
  assert.equal(imp2.body.idempotent, true);

  // Replay #2: a DIFFERENT idempotency key but the same underlying
  // (watermark,user,device,file) import identity — recordImport's own dedupe
  // recognizes this as the same recorded import; still no duplicate anomaly.
  const imp3 = await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: importerBearer, 'idempotency-key': 'rp-i2' },
    body: { watermarkId, fileMeta: { sha256: 'file-rp' } }, ip: '7.7.7.7',
  }));
  assert.equal(imp3.status, 200);

  const anomalies = await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'cross_user_import' });
  assert.equal(anomalies.length, 1, 'exactly one anomaly survives across both replay paths');
  assert.equal((await ctx.repo.watermarkImports.find({ watermarkId })).length, 1, 'still just one tracer row too');
});

// ===========================================================================
// P2 — admin transfer-flow feed (browse export→import provenance)
// ===========================================================================

test('admin/reports/transfers: flow feed lists newest-export-first with real importer identity + decrypted IP + importCount', async () => {
  const ctx = makeCtx();
  const { member: exporter, memberBearer: exporterBearer, admin, adminBearer } = await transferFixture(ctx, { exportEnabled: true });

  const expA = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: exporterBearer, 'idempotency-key': 'ta-1' }, body: { fileMeta: { sha256: 'file-a' } }, ip: '8.8.8.8',
  }));
  const wmA = expA.body.watermarkId;
  ctx.clock.advance(1000); // B exported strictly after A
  const expB = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: exporterBearer, 'idempotency-key': 'tb-1' }, body: { fileMeta: { sha256: 'file-b' } }, ip: '8.8.8.8',
  }));
  const wmB = expB.body.watermarkId;

  const importer = await makeActiveUser(ctx, { email: 'timp@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: importer._id, field: 'importEnabled', value: true });
  const importerBearer = await bearerFor(ctx, 'timp@superworks.com', 'password12345', 'dev-ti');
  await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: importerBearer, 'idempotency-key': 'ti-1' },
    body: { watermarkId: wmA, userId: 'FORGED-ID', fileMeta: { sha256: 'file-a' } }, ip: '9.9.9.9',
  }));

  const res = await routes.handleRequest(ctx, req('GET', '/admin/reports/transfers', { headers: { authorization: adminBearer } }));
  assert.equal(res.status, 200);
  assert.equal(res.body.transfers.length, 2);
  assert.equal(res.body.transfers[0].watermarkId, wmB, 'newest export (B) first');
  assert.equal(res.body.transfers[1].watermarkId, wmA);

  const flowA = res.body.transfers[1];
  assert.equal(flowA.importCount, 1);
  assert.equal(flowA.imports.length, 1);
  assert.equal(flowA.imports[0].userId, importer._id, 'real (server-stamped) importer identity, not the forged body value');
  assert.equal(flowA.imports[0].ip, '9.9.9.9', 'decrypted importer IP');
  assert.equal(flowA.imports[0].deviceId, 'dev-ti');
  assert.ok(flowA.imports[0].at);
  assert.equal(flowA.export.userId, exporter._id);
  assert.equal(flowA.export.fileSha256, 'file-a');

  const flowB = res.body.transfers[0];
  assert.equal(flowB.importCount, 0);
  assert.deepEqual(flowB.imports, []);
});

test('admin/reports/transfers: window excludes an export older than the requested days', async () => {
  const ctx = makeCtx();
  const { admin, memberBearer: exporterBearer } = await transferFixture(ctx, { exportEnabled: true });

  const oldExp = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: exporterBearer, 'idempotency-key': 'old-1' }, body: { fileMeta: { sha256: 'old-file' } }, ip: '8.8.8.8',
  }));
  const wmOld = oldExp.body.watermarkId;
  ctx.clock.advance(8 * 24 * 3600e3); // 8 days later — past the default 7-day window
  // The pre-advance access token is now past its 15-minute TTL — sign in again
  // so the "new" export call itself isn't rejected as unauthenticated.
  const freshExporterBearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'dev-m');
  const newExp = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: freshExporterBearer, 'idempotency-key': 'new-1' }, body: { fileMeta: { sha256: 'new-file' } }, ip: '8.8.8.8',
  }));
  const wmNew = newExp.body.watermarkId;

  // Called directly against the service (mirrors the reports/timeline window
  // test) so the fixed-TTL admin access token minted before the clock advance
  // doesn't itself expire and mask the assertion under test.
  const out = await reporting.transferFlows(ctx, { adminId: admin._id });
  const ids = out.transfers.map(t => t.watermarkId);
  assert.ok(ids.includes(wmNew), 'recent export is in the window');
  assert.ok(!ids.includes(wmOld), 'an 8-day-old export is outside the default 7-day window');

  // days is clamped to a max of 7 server-side (Addendum B retention), so even
  // an explicit days=10 request still excludes the 8-day-old export.
  const wide = await reporting.transferFlows(ctx, { adminId: admin._id, days: 10 });
  const wideIds = wide.transfers.map(t => t.watermarkId);
  assert.ok(!wideIds.includes(wmOld), 'days is clamped server-side to at most 7');
});

test('admin/reports/transfers: a non-admin member is refused (403); no flow data leaks', async () => {
  const ctx = makeCtx();
  const { memberBearer: exporterBearer } = await transferFixture(ctx, { exportEnabled: true });
  await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: exporterBearer, 'idempotency-key': 'na-1' }, body: { fileMeta: { sha256: 'f' } }, ip: '8.8.8.8',
  }));
  const res = await routes.handleRequest(ctx, req('GET', '/admin/reports/transfers', { headers: { authorization: exporterBearer } }));
  assert.equal(res.status, 403);
  assert.equal(res.body.transfers, undefined, 'no flow data in a non-admin response');
});

test('admin/reports/transfers: response is metadata only — no file content or unrelated fields', async () => {
  const ctx = makeCtx();
  const { memberBearer: exporterBearer, admin, adminBearer } = await transferFixture(ctx, { exportEnabled: true });
  const exp = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: exporterBearer, 'idempotency-key': 'nc-1' },
    body: { fileMeta: { sha256: 'file-nc', name: 'secret.json', size: 99999 } }, ip: '8.8.8.8',
  }));
  const wm = exp.body.watermarkId;
  const importer = await makeActiveUser(ctx, { email: 'ncimp@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: importer._id, field: 'importEnabled', value: true });
  const importerBearer = await bearerFor(ctx, 'ncimp@superworks.com', 'password12345', 'dev-nci');
  await routes.handleRequest(ctx, req('POST', '/import/authorize', {
    headers: { authorization: importerBearer, 'idempotency-key': 'nc-i1' }, body: { watermarkId: wm, fileMeta: { sha256: 'file-nc' } }, ip: '9.9.9.9',
  }));

  const res = await routes.handleRequest(ctx, req('GET', '/admin/reports/transfers', { headers: { authorization: adminBearer } }));
  const flow = res.body.transfers.find(t => t.watermarkId === wm);
  assert.deepEqual(Object.keys(flow).sort(), ['export', 'imports', 'importCount', 'watermarkId'].sort());
  assert.deepEqual(Object.keys(flow.export).sort(), ['deviceId', 'email', 'exportedAt', 'fileSha256', 'userId'].sort());
  for (const imp of flow.imports) {
    assert.deepEqual(Object.keys(imp).sort(), ['at', 'deviceId', 'email', 'ip', 'userId'].sort());
  }
  // Emails are resolved for the admin feed (who exported -> who imported).
  assert.ok(flow.export.email && flow.export.email.includes('@'), 'exporter email is resolved');
  assert.equal(flow.imports[0].email, 'ncimp@superworks.com', 'importer email is resolved');
  const json = JSON.stringify(res.body);
  assert.ok(!json.includes('secret.json'), 'file name never appears in the admin feed');
  assert.ok(!json.includes('99999'), 'file size never appears in the admin feed');
  assert.ok(!json.toLowerCase().includes('password'), 'no credential material in the admin feed');
});

// ===========================================================================
// P2 STEP 5 — anomaly engine rules (travel, new-device, repeated-fail, dead-man)
// ===========================================================================

test('anomaly/travel: assessTravel guards against every common false positive', () => {
  const cfg = { impossibleTravelKmh: 900, impossibleTravelWindowMs: 24 * 3600e3, minTravelMinutes: 5, minTravelKm: 100 };
  const LON = { lat: 51.5, lon: -0.1, asn: 'AS1', country: 'GB' };
  const NYC = { lat: 40.7, lon: -74.0, asn: 'AS2', country: 'US' };
  const t = (m) => new Date(1_700_000_000_000 + m * 60000);
  // Genuine impossible travel: London→NYC (cross-border) in 10 min.
  assert.equal(assessImpossible(cfg, { ...LON, at: t(0) }, { ...NYC, at: t(10) }), true);
  // Too soon (< min minutes) → divide-by-~0 guard.
  assert.equal(assessImpossible(cfg, { ...LON, at: t(0) }, { ...NYC, at: t(2) }), false);
  // Same ASN (VPN/carrier) → suppressed.
  assert.equal(assessImpossible(cfg, { ...LON, asn: 'AS9', at: t(0) }, { ...NYC, asn: 'AS9', at: t(10) }), false);
  // Too close (< min km) → coarse-geo jitter, not travel.
  assert.equal(assessImpossible(cfg, { lat: 51.5, lon: -0.1, asn: 'A', country: 'GB', at: t(0) }, { lat: 51.51, lon: -0.11, asn: 'B', country: 'GB', at: t(30) }), false);
  // Country-only (no coordinates) → never fires.
  assert.equal(assessImpossible(cfg, { country: 'GB', at: t(0) }, { country: 'US', at: t(30) }), false);
  // Plenty of time to make the trip → fine.
  assert.equal(assessImpossible(cfg, { ...LON, at: t(0) }, { ...NYC, at: t(600) }), false);
  // REVIEW FIX: same-country Wi-Fi↔cellular handoff (different ASN, fast, SAME
  // country) is the dominant mobile false positive — must NOT flag critical.
  const SF = { lat: 37.77, lon: -122.41, asn: 'AS-home', country: 'US' };
  const LA = { lat: 34.05, lon: -118.24, asn: 'AS-carrier', country: 'US' };
  assert.equal(assessImpossible(cfg, { ...SF, at: t(0) }, { ...LA, at: t(10) }), false, 'same-country teleport suppressed');
});
function assessImpossible(cfg, a, b) { return presence.assessTravel(a, b, cfg).impossible; }

test('anomaly/new-device: first device is silent; a second device warns + emails admin', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await makeActiveUser(ctx, { email: 'u@superworks.com', password: 'password12345' });
  await auth.login(ctx, { email: 'u@superworks.com', password: 'password12345', deviceId: 'dev-1', ip: '8.8.8.8' });
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'new_device' })).length, 0, 'first device is not anomalous');
  const mailsBefore = ctx.mailer.sent.length;
  await auth.login(ctx, { email: 'u@superworks.com', password: 'password12345', deviceId: 'dev-2', ip: '8.8.8.8' });
  const nd = await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'new_device' });
  assert.equal(nd.length, 1, 'second device warns');
  assert.equal(nd[0].deviceId, 'dev-2');
  assert.ok(ctx.mailer.sent.length > mailsBefore, 'admin is emailed about the new device');
});

test('anomaly/travel: same device from far-apart IPs in a short window → critical impossible-travel', async () => {
  const ctx = makeCtx({ geo: geoByIp({
    '1.1.1.1': { country: 'GB', lat: 51.5, lon: -0.1, asn: 'AS1' },
    '2.2.2.2': { country: 'US', lat: 40.7, lon: -74.0, asn: 'AS2' },
  }) });
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await makeActiveUser(ctx, { email: 'trav@superworks.com', password: 'password12345' });
  await auth.login(ctx, { email: 'trav@superworks.com', password: 'password12345', deviceId: 'dev-T', ip: '1.1.1.1' });
  ctx.clock.advance(10 * 60 * 1000); // 10 minutes later
  await auth.login(ctx, { email: 'trav@superworks.com', password: 'password12345', deviceId: 'dev-T', ip: '2.2.2.2' });
  const it = await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'impossible_travel' });
  assert.equal(it.length, 1);
  assert.equal(it[0].severity, 'critical');
});

test('anomaly/repeated-fail: credential spray across accounts from one IP trips a per-IP anomaly', async () => {
  const ctx = makeCtx();
  ctx.config = { ...ctx.config, anomaly: { ...ctx.config.anomaly, repeatedFailThreshold: 3 } };
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  // Three failed logins across DIFFERENT (nonexistent) emails from one IP.
  for (let i = 0; i < 3; i++) {
    await auth.login(ctx, { email: `ghost${i}@superworks.com`, password: 'x', deviceId: 'd', ip: '9.9.9.9' }).catch(() => {});
  }
  const rf = await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'repeated_failed_logins' });
  assert.ok(rf.length >= 1, 'per-IP spray is detected even though no single account was targeted');
});

test('anomaly/dead-man: silent active devices fire once; terminal-state devices are excluded', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const old = new Date(ctx.clock.nowMs() - 8 * 24 * 3600e3); // 8 days silent (> deadManDays=7)
  await ctx.repo.devices.insert({ _id: 'dev-old', userId: 'u1', status: 'active', firstSeen: old, lastSeen: old });
  await ctx.repo.devices.insert({ _id: 'dev-fresh', userId: 'u2', status: 'active', firstSeen: old, lastSeen: ctx.clock.now() });
  await ctx.repo.devices.insert({ _id: 'dev-wiped', userId: 'u3', status: 'wiped', firstSeen: old, lastSeen: old });
  const res = await presence.deadManScan(ctx);
  assert.equal(res.fired, 1, 'only the silent ACTIVE device fires');
  const dm = await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'dead_man' });
  assert.equal(dm.length, 1);
  assert.equal(dm[0].deviceId, 'dev-old');
  // Re-scan without a heartbeat → same silence episode → no duplicate alert.
  await presence.deadManScan(ctx);
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'dead_man' })).length, 1);
});

// ===========================================================================
// P2 STEP 6 — remote-command queue (unilateral effects, device-bound, replay-safe)
// ===========================================================================

const commandsLib = require('./lib/commands');

// admin + member with two logged-in devices (two session families).
async function commandFixture(ctx) {
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  const s1 = await auth.login(ctx, { email: 'm@superworks.com', password: 'password12345', deviceId: 'dev-1', ip: '8.8.8.8' });
  const s2 = await auth.login(ctx, { email: 'm@superworks.com', password: 'password12345', deviceId: 'dev-2', ip: '8.8.8.8' });
  return { admin, member, s1, s2 };
}

test('commands: force_logout revokes ALL of a user\'s sessions immediately at enqueue (unilateral)', async () => {
  const ctx = makeCtx();
  const { admin, s1, s2 } = await commandFixture(ctx);
  await commandsLib.enqueueCommand(ctx, { adminId: admin._id, deviceId: 'dev-1', type: 'force_logout' });
  // Both families are dead even though NO device ever polled.
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-1' }), (e) => e.status === 401);
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s2.refreshToken, deviceId: 'dev-2' }), (e) => e.status === 401);
});

test('commands: deprovision flips status via the permission_changes ledger + revokes sessions + marks device', async () => {
  const ctx = makeCtx();
  const { admin, member, s2 } = await commandFixture(ctx);
  await commandsLib.enqueueCommand(ctx, { adminId: admin._id, deviceId: 'dev-1', type: 'deprovision' });
  assert.equal((await ctx.repo.users.findById(member._id)).status, 'deprovisioned');
  const pc = await ctx.repo.permissionChanges.find({ field: 'status', to: 'deprovisioned' });
  assert.equal(pc.length, 1, 'status change is chained in permission_changes');
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
  assert.equal((await ctx.repo.devices.findById('dev-1')).status, 'deprovisioned');
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s2.refreshToken, deviceId: 'dev-2' }), (e) => e.status === 401);
});

test('commands: disable_account suspends the user + revokes sessions', async () => {
  const ctx = makeCtx();
  const { admin, member, s1 } = await commandFixture(ctx);
  await commandsLib.enqueueCommand(ctx, { adminId: admin._id, deviceId: 'dev-1', type: 'disable_account' });
  assert.equal((await ctx.repo.users.findById(member._id)).status, 'suspended');
  await assert.rejects(() => auth.refresh(ctx, { refreshToken: s1.refreshToken, deviceId: 'dev-1' }), (e) => e.status === 401);
});

test('commands: poll→ack lifecycle audits each transition; ack is idempotent (replay-safe)', async () => {
  const ctx = makeCtx();
  const { admin, member } = await commandFixture(ctx);
  const cmd = await commandsLib.enqueueCommand(ctx, { adminId: admin._id, deviceId: 'dev-1', type: 'wipe_claude_creds' });
  // Poll (own device) delivers + marks sent.
  const poll = await commandsLib.pollCommands(ctx, { userId: member._id, deviceId: 'dev-1' });
  assert.equal(poll.commands.length, 1);
  assert.equal(poll.commands[0].commandId, cmd.commandId);
  assert.equal((await ctx.repo.commands.findById(cmd.commandId)).status, 'sent');
  // Ack, then replay the ack.
  const a1 = await commandsLib.ackCommand(ctx, { userId: member._id, deviceId: 'dev-1', commandId: cmd.commandId, result: 'ok' });
  assert.equal(a1.status, 'acked');
  const a2 = await commandsLib.ackCommand(ctx, { userId: member._id, deviceId: 'dev-1', commandId: cmd.commandId, result: 'ok' });
  assert.equal(a2.idempotent, true, 'replayed ack is a no-op');
  // Each of pending/sent/acked appears exactly once (idempotency-keyed).
  for (const st of ['pending', 'sent', 'acked']) {
    assert.equal((await ctx.repo.auditEvents.find({ commandId: cmd.commandId, commandStatus: st })).length, 1, `one ${st} audit`);
  }
});

test('commands: poll/ack are bound to the token device — cross-device and cross-user are refused', async () => {
  const ctx = makeCtx();
  const { admin, member } = await commandFixture(ctx);
  const other = await makeActiveUser(ctx, { email: 'other@superworks.com', password: 'password12345' });
  const cmd = await commandsLib.enqueueCommand(ctx, { adminId: admin._id, deviceId: 'dev-1', type: 'wipe_claude_creds' });
  // Another user cannot poll this device's commands.
  await assert.rejects(() => commandsLib.pollCommands(ctx, { userId: other._id, deviceId: 'dev-1' }), (e) => e.status === 403);
  // The user's OTHER device (dev-2) cannot ack a command aimed at dev-1.
  await assert.rejects(() => commandsLib.ackCommand(ctx, { userId: member._id, deviceId: 'dev-2', commandId: cmd.commandId }), (e) => e.status === 403);
});

test('commands: only an admin enqueues; unknown type/device are rejected', async () => {
  const ctx = makeCtx();
  const { admin, member } = await commandFixture(ctx);
  await assert.rejects(() => commandsLib.enqueueCommand(ctx, { adminId: member._id, deviceId: 'dev-1', type: 'wipe_claude_creds' }), (e) => e.status === 403);
  await assert.rejects(() => commandsLib.enqueueCommand(ctx, { adminId: admin._id, deviceId: 'dev-1', type: 'nuke' }), (e) => e.status === 400);
  await assert.rejects(() => commandsLib.enqueueCommand(ctx, { adminId: admin._id, deviceId: 'no-such-device', type: 'wipe_claude_creds' }), (e) => e.status === 404);
});

test('commands/http: enqueue→poll→ack over HTTP with deviceId taken from the token', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  const memberBearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'dev-1'); // creates device dev-1
  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', 'password12345', 'dev-a');
  const enq = await routes.handleRequest(ctx, req('POST', '/admin/commands', { headers: { authorization: adminBearer }, body: { deviceId: 'dev-1', type: 'wipe_claude_creds' } }));
  assert.equal(enq.status, 201);
  const poll = await routes.handleRequest(ctx, req('POST', '/commands/poll', { headers: { authorization: memberBearer }, body: {} }));
  assert.equal(poll.status, 200);
  assert.equal(poll.body.commands.length, 1);
  const ack = await routes.handleRequest(ctx, req('POST', '/commands/ack', { headers: { authorization: memberBearer }, body: { commandId: enq.body.commandId, result: 'ok' } }));
  assert.equal(ack.status, 200);
  assert.equal(ack.body.status, 'acked');
});

// ===========================================================================
// P2 STEP 8 — admin monitoring toggle (recorded in permission_changes)
// ===========================================================================

test('monitoring: admin toggles a user\'s monitoring; default on; recorded; non-admin refused', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  assert.equal(member.monitoringEnabled, true, 'default is on for a managed tool');
  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', 'password12345', 'dev-a');
  const res = await routes.handleRequest(ctx, req('POST', '/admin/monitoring', { headers: { authorization: adminBearer }, body: { targetUserId: member._id, enabled: false } }));
  assert.equal(res.status, 200);
  assert.equal((await ctx.repo.users.findById(member._id)).monitoringEnabled, false);
  assert.ok((await ctx.repo.permissionChanges.find({ field: 'monitoringEnabled' })).length >= 1);
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
  // Member cannot toggle monitoring.
  const memberBearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'dev-m');
  const denied = await routes.handleRequest(ctx, req('POST', '/admin/monitoring', { headers: { authorization: memberBearer }, body: { targetUserId: admin._id, enabled: false } }));
  assert.equal(denied.status, 403);
});

// ===========================================================================
// P2 STEP 9 — admin reporting APIs (per-endpoint gated, 7-day windowed)
// ===========================================================================

const reporting = require('./lib/reporting');

test('reports: EVERY report route is admin-gated — a member gets 403, an admin 200', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', 'password12345', 'dev-a');
  const memberBearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'dev-m');
  for (const path of ['/admin/reports/timeline', '/admin/reports/devices', '/admin/reports/alerts', '/admin/reports/storage', '/admin/reports/users']) {
    const denied = await routes.handleRequest(ctx, req('GET', path, { headers: { authorization: memberBearer } }));
    assert.equal(denied.status, 403, `${path} must refuse a member`);
    const ok = await routes.handleRequest(ctx, req('GET', path, { headers: { authorization: adminBearer } }));
    assert.equal(ok.status, 200, `${path} must serve an admin`);
  }
});

test('reports/timeline: 7-day window excludes older events; admin sees the decrypted IP', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'u-old', ip: '1.1.1.1' }); // t0
  ctx.clock.advance(8 * 24 * 3600e3);
  await audit.recordEvent(ctx, { eventType: 'export', userId: 'u-new', ip: '8.8.8.8' }); // t0 + 8d
  const tl = await reporting.activityTimeline(ctx, { adminId: admin._id });
  const users = tl.events.map(e => e.userId);
  assert.ok(users.includes('u-new'), 'recent event is in the window');
  assert.ok(!users.includes('u-old'), 'an 8-day-old event is outside the 7-day window');
  const ev = tl.events.find(e => e.userId === 'u-new');
  assert.equal(ev.ip, '8.8.8.8', 'admin sees the decrypted IP');
});

test('reports/timeline: userId is an admin-scoped filter, not the caller identity', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'alice' });
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'bob' });
  const onlyAlice = await reporting.activityTimeline(ctx, { adminId: admin._id, userId: 'alice' });
  assert.ok(onlyAlice.events.length >= 1 && onlyAlice.events.every(e => e.userId === 'alice'));
});

test('reports/alerts: only warn/critical events appear in the alerts feed', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'u1', severity: 'info' });
  await anomaly.emit(ctx, { severity: 'warn', userId: 'u1', reason: 'new_device', dedupeKey: 'a1' });
  await anomaly.emit(ctx, { severity: 'critical', userId: 'u1', reason: 'impossible_travel', dedupeKey: 'a2' });
  const feed = await reporting.alertsFeed(ctx, { adminId: admin._id });
  assert.equal(feed.alerts.length, 2);
  assert.ok(feed.alerts.every(a => a.severity === 'warn' || a.severity === 'critical'));
});

test('reports/storage: percent is clamped to [0,100] even past capacity', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  ctx.repo.stats = async () => ({ estimatedBytes: 999 * 1024 * 1024 * 1024 }); // way over 512MB
  const s = await reporting.storagePercent(ctx, { adminId: admin._id });
  assert.equal(s.percent, 100);
  ctx.repo.stats = async () => ({ estimatedBytes: 0 });
  assert.equal((await reporting.storagePercent(ctx, { adminId: admin._id })).percent, 0);
});

test('reports/devices: inventory lists devices with decrypted last IP for the admin', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  await auth.login(ctx, { email: 'm@superworks.com', password: 'password12345', deviceId: 'dev-1', ip: '203.0.113.5' });
  const inv = await reporting.deviceInventory(ctx, { adminId: admin._id });
  const d = inv.devices.find(x => x.deviceId === 'dev-1');
  assert.ok(d);
  assert.equal(d.userId, member._id);
  assert.equal(d.email, 'm@superworks.com', 'admin sees the device owner by email, not just a raw user id');
  assert.equal(d.lastIp, '203.0.113.5', 'admin sees the decrypted device IP');
});

// ===========================================================================
// ADMIN USERS DIRECTORY — every user by email, with a per-user ISSUES list
// ===========================================================================

test('reports/users: directory lists every user with decrypted email + role/status/entitlement flags', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'zz@superworks.com', password: 'password12345' });
  const dir = await reporting.usersDirectory(ctx, { adminId: admin._id });
  assert.equal(dir.users.length, 2);
  const m = dir.users.find(u => u.userId === member._id);
  assert.ok(m, 'member appears in the directory');
  assert.equal(m.email, 'zz@superworks.com', 'email is decrypted');
  assert.equal(m.role, 'member');
  assert.equal(m.status, 'active');
  assert.equal(m.emailVerified, true);
  assert.equal(m.importEnabled, false);
  assert.equal(m.exportEnabled, false);
  assert.equal(m.monitoringEnabled, true);
  assert.equal(m.entitlementExpiresAt, null);
  assert.equal(m.entitlementExpired, false);
  assert.deepEqual(m.geoFenceCountries, []);
  assert.equal(m.noticeAcceptedAt, null);
  assert.ok(m.createdAt);
  assert.equal(m.deviceCount, 0);
  assert.equal(m.lastSeen, null);
  assert.equal(m.openAlerts, 0);
  assert.deepEqual(m.issues, ['Notice not accepted'], 'a fresh user has not accepted the notice yet');
});

test('reports/users: non-admin caller is refused (403); admin succeeds', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'plain@superworks.com', password: 'password12345' });
  await assert.rejects(() => reporting.usersDirectory(ctx, { adminId: member._id }), (e) => e.status === 403);
});

test('reports/users: issues are computed per-user and users with issues sort before healthy users', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const healthy = await makeActiveUser(ctx, { email: 'healthy@superworks.com', password: 'password12345' });
  await ctx.repo.users.updateById(healthy._id, { noticeAcceptedAt: ctx.clock.now() });

  const suspended = await makeActiveUser(ctx, { email: 'suspended@superworks.com', password: 'password12345' });
  await ctx.repo.users.updateById(suspended._id, { status: 'suspended' });

  const paused = await makeActiveUser(ctx, { email: 'paused@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: paused._id, field: 'monitoringEnabled', value: false });

  const expired = await makeActiveUser(ctx, { email: 'expired@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: expired._id, field: 'entitlementExpiresAt', value: new Date(ctx.clock.nowMs() - 60000) });

  const dir = await reporting.usersDirectory(ctx, { adminId: admin._id });

  assert.deepEqual(dir.users.find(u => u.email === 'suspended@superworks.com').issues, ['Suspended', 'Notice not accepted']);
  assert.deepEqual(dir.users.find(u => u.email === 'paused@superworks.com').issues, ['Monitoring paused', 'Notice not accepted']);
  assert.deepEqual(dir.users.find(u => u.email === 'expired@superworks.com').issues, ['Access expired', 'Notice not accepted']);
  assert.deepEqual(dir.users.find(u => u.email === 'healthy@superworks.com').issues, [], 'no issues = healthy');

  const emails = dir.users.map(u => u.email);
  assert.deepEqual(emails, [
    'expired@superworks.com',
    'paused@superworks.com',
    'suspended@superworks.com',
    'admin@superworks.com',
    'healthy@superworks.com',
  ], 'users with issues sort first (issues.length desc), then by email asc; healthy users sort last');
});

test('reports/users: deviceCount and openAlerts are correctly joined per user', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'joined@superworks.com', password: 'password12345' });
  await auth.login(ctx, { email: 'joined@superworks.com', password: 'password12345', deviceId: 'dev-a', ip: '9.9.9.9' });
  ctx.clock.advance(1000);
  // Disable the automatic new-device anomaly so this test's only warn/critical
  // events are the two explicit ones below (isolates the join, not anomaly.js).
  ctx.config.anomaly.newDeviceIsAnomaly = false;
  await auth.login(ctx, { email: 'joined@superworks.com', password: 'password12345', deviceId: 'dev-b', ip: '9.9.9.8' });
  const latestSeen = ctx.clock.now();

  await anomaly.emit(ctx, { severity: 'warn', userId: member._id, reason: 'new_device', dedupeKey: 'ud1' });
  await anomaly.emit(ctx, { severity: 'critical', userId: member._id, reason: 'impossible_travel', dedupeKey: 'ud2' });
  await audit.recordEvent(ctx, { eventType: 'login', userId: member._id, severity: 'info' }); // must not count as an alert

  const dir = await reporting.usersDirectory(ctx, { adminId: admin._id });
  const m = dir.users.find(u => u.userId === member._id);
  assert.equal(m.deviceCount, 2, 'both devices are counted');
  assert.equal(new Date(m.lastSeen).getTime(), latestSeen.getTime(), 'lastSeen is the MAX across the user\'s devices');
  assert.equal(m.openAlerts, 2, 'only the warn+critical events count, not the info login');
  assert.ok(m.issues.includes('2 open alert(s)'));
});

test('reports/users: a decrypt failure for the email yields null instead of throwing', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'broken@superworks.com', password: 'password12345' });
  await ctx.repo.users.updateById(member._id, { emailEnc: 'not-valid-ciphertext' });
  const dir = await reporting.usersDirectory(ctx, { adminId: admin._id });
  const m = dir.users.find(u => u.userId === member._id);
  assert.ok(m, 'the user still appears in the directory');
  assert.equal(m.email, null, 'a decrypt failure yields null, never a thrown error');
});

test('reports/users: exposes blockedCountries and adds a "Country-blocked" issue when a per-user country deny-list is set', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'blk@superworks.com', password: 'password12345' });
  await access.setBlockedCountries(ctx, { adminId: admin._id, targetUserId: member._id, countries: ['US', 'GB'] });
  const dir = await reporting.usersDirectory(ctx, { adminId: admin._id });
  const m = dir.users.find(u => u.userId === member._id);
  assert.deepEqual(m.blockedCountries, ['US', 'GB']);
  assert.ok(m.issues.includes('Country-blocked'));
});

// F3 provenance: WHO created this user, joined from the same per-user email
// decrypt pass usersDirectory already performs — zero extra reads.
test('reports/users: createdBy/createdByEmail surface for a managed user; a self-signup user has both null', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'bossdir@superworks.com', password: 'password12345' });
  const res = await admin.createManagedUser(ctx, { adminId: boss.userId, email: 'empdir@superworks.com', password: 'password12345' });
  const selfSignup = await makeActiveUser(ctx, { email: 'selfsignup@superworks.com', password: 'password12345' });

  const dir = await reporting.usersDirectory(ctx, { adminId: boss.userId });
  const emp = dir.users.find(u => u.userId === res.userId);
  assert.equal(emp.createdBy, boss.userId);
  assert.equal(emp.createdByEmail, 'bossdir@superworks.com');

  const self = dir.users.find(u => u.userId === selfSignup._id);
  assert.equal(self.createdBy, null);
  assert.equal(self.createdByEmail, null);
});

test('reports/users: issues[] regression — a fresh managed user still shows only "Notice not accepted" (createdBy is additive)', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'bossreg@superworks.com', password: 'password12345' });
  const res = await admin.createManagedUser(ctx, { adminId: boss.userId, email: 'empreg@superworks.com', password: 'password12345' });
  const dir = await reporting.usersDirectory(ctx, { adminId: boss.userId });
  const emp = dir.users.find(u => u.userId === res.userId);
  assert.deepEqual(emp.issues, ['Notice not accepted']);
});

test('reports/users: a creator-email decrypt failure yields createdByEmail:null, never a throw', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'bossbroken@superworks.com', password: 'password12345' });
  const res = await admin.createManagedUser(ctx, { adminId: boss.userId, email: 'empbroken@superworks.com', password: 'password12345' });
  await ctx.repo.users.updateById(boss.userId, { emailEnc: 'not-valid-ciphertext' });
  const dir = await reporting.usersDirectory(ctx, { adminId: boss.userId });
  const emp = dir.users.find(u => u.userId === res.userId);
  assert.ok(emp, 'employee still appears');
  assert.equal(emp.createdBy, boss.userId);
  assert.equal(emp.createdByEmail, null, 'a decrypt failure for the creator email yields null, never throws');
});

// Onboarding (F3): a freshly created managed user has no device yet;
// signing in for the first time (which stamps a device doc, same as the
// existing deviceCount-join test above) flips deviceCount 0 -> 1.
test('reports/users: onboarding — a fresh managed user has deviceCount 0, then 1 after first sign-in', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'bossonb@superworks.com', password: 'password12345' });
  const res = await admin.createManagedUser(ctx, { adminId: boss.userId, email: 'emponb@superworks.com', password: 'password12345' });

  const before = await reporting.usersDirectory(ctx, { adminId: boss.userId });
  const beforeRow = before.users.find(u => u.userId === res.userId);
  assert.equal(beforeRow.deviceCount, 0);
  assert.equal(beforeRow.lastSeen, null);

  await auth.login(ctx, { email: 'emponb@superworks.com', password: 'password12345', deviceId: 'onb-dev-1', ip: '9.9.9.9' });

  const after = await reporting.usersDirectory(ctx, { adminId: boss.userId });
  const afterRow = after.users.find(u => u.userId === res.userId);
  assert.equal(afterRow.deviceCount, 1);
  assert.ok(afterRow.lastSeen);
});

test('reports/users/http: GET /admin/reports/users returns 200 for admin, 403 for a member', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await makeActiveUser(ctx, { email: 'httpm@superworks.com', password: 'password12345' });
  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', 'password12345', 'dev-a');
  const memberBearer = await bearerFor(ctx, 'httpm@superworks.com', 'password12345', 'dev-m');
  const denied = await routes.handleRequest(ctx, req('GET', '/admin/reports/users', { headers: { authorization: memberBearer } }));
  assert.equal(denied.status, 403);
  const ok = await routes.handleRequest(ctx, req('GET', '/admin/reports/users', { headers: { authorization: adminBearer } }));
  assert.equal(ok.status, 200);
  assert.ok(Array.isArray(ok.body.users));
  const emails = ok.body.users.map(u => u.email);
  assert.ok(emails.includes('httpm@superworks.com'));
});

// ===========================================================================
// USAGE TRACKING + REPORTS (additive, storage-lean) — spec f1a-usage-backend.
// Backend touch-points: lib/usagestore.js (self-scoped store, NOT reporting.js
// — see its header comment), reporting.usageOverview (admin fleet view),
// POST /usage/snapshot + GET /usage/me + GET /admin/reports/usage.
// NOT an audit event: usage snapshots must never touch CORE_FIELDS/the hash
// chain — proven by the hash-chain guard test at the end of this section.
// ===========================================================================

test('reports/usage: usageOverview is admin-gated — a member gets 403; an admin sees decrypted email + account label', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'usageadmin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'usagemember@superworks.com', password: 'password12345' });
  await usagestore.recordUsageSnapshot(ctx, {
    userId: member._id,
    accounts: [{
      accountUuid: 'a1', organizationUuid: 'o1', label: 'work@x.com', fiveHour: 40, sevenDay: 60,
      fiveHourResetsAt: '2026-07-17T15:00:00.000Z', sevenDayResetsAt: '2026-07-19T13:30:00.000Z',
    }],
  });

  await assert.rejects(() => reporting.usageOverview(ctx, { adminId: member._id }), (e) => e.status === 403);

  const out = await reporting.usageOverview(ctx, { adminId: admin._id });
  assert.equal(out.rows.length, 1);
  const row = out.rows[0];
  assert.equal(row.userId, member._id);
  assert.equal(row.email, 'usagemember@superworks.com', 'admin sees the decrypted email');
  assert.equal(row.accountLabel, 'work@x.com', 'admin sees the decrypted account label');
  assert.equal(row.accountUuid, 'a1');
  assert.equal(row.organizationUuid, 'o1');
  assert.equal(row.fiveHour, 40);
  assert.equal(row.sevenDay, 60);
  assert.equal(row.fiveHourResetsAt, '2026-07-17T15:00:00.000Z', 'the 5-hour reset instant projects through for display');
  assert.equal(row.sevenDayResetsAt, '2026-07-19T13:30:00.000Z', 'the weekly reset instant projects through for display');
  assert.ok(row.updatedAt);
});

test('reports/usage: rows sort heaviest-first — sevenDay desc, then fiveHour desc, deterministically', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'usagesortadmin@superworks.com', password: 'password12345', role: 'admin' });
  const m1 = await makeActiveUser(ctx, { email: 'sort1@superworks.com', password: 'password12345' });
  const m2 = await makeActiveUser(ctx, { email: 'sort2@superworks.com', password: 'password12345' });
  await usagestore.recordUsageSnapshot(ctx, { userId: m1._id, accounts: [{ accountUuid: 'lo', organizationUuid: 'o', label: 'lo', fiveHour: 90, sevenDay: 10 }] });
  await usagestore.recordUsageSnapshot(ctx, { userId: m2._id, accounts: [{ accountUuid: 'hi', organizationUuid: 'o', label: 'hi', fiveHour: 5, sevenDay: 95 }] });
  const out = await reporting.usageOverview(ctx, { adminId: admin._id });
  assert.deepEqual(out.rows.map(r => r.accountUuid), ['hi', 'lo'], 'the heavier weekly (sevenDay) user sorts first');
});

test('reports/usage: window-filtered by updatedAt — a snapshot older than the window is excluded', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'usagewinadmin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'usagewinmember@superworks.com', password: 'password12345' });
  await usagestore.recordUsageSnapshot(ctx, { userId: member._id, accounts: [{ accountUuid: 'old', organizationUuid: 'o', label: 'old', fiveHour: 1, sevenDay: 1 }] });
  ctx.clock.advance(8 * 24 * 3600e3);
  await usagestore.recordUsageSnapshot(ctx, { userId: member._id, accounts: [{ accountUuid: 'new', organizationUuid: 'o', label: 'new', fiveHour: 1, sevenDay: 1 }] });
  const out = await reporting.usageOverview(ctx, { adminId: admin._id });
  const uuids = out.rows.map(r => r.accountUuid);
  assert.ok(uuids.includes('new'), 'the recent snapshot is inside the window');
  assert.ok(!uuids.includes('old'), 'an 8-day-old snapshot is outside the 7-day window');
});

test('reports/usage: a label decrypt failure yields null instead of throwing (row still appears)', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'usagebrokenadmin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'usagebrokenmember@superworks.com', password: 'password12345' });
  await usagestore.recordUsageSnapshot(ctx, { userId: member._id, accounts: [{ accountUuid: 'broken', organizationUuid: 'o', label: 'x', fiveHour: 1, sevenDay: 1 }] });
  await ctx.repo.usageSnapshots.updateById(`${member._id}|broken::o`, { labelEnc: 'not-valid-ciphertext' });
  const out = await reporting.usageOverview(ctx, { adminId: admin._id });
  const row = out.rows.find(r => r.accountUuid === 'broken');
  assert.ok(row, 'the row still appears despite the decrypt failure');
  assert.equal(row.accountLabel, null);
});

test('reports/usage: a user email decrypt failure yields a null email, row still appears', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'usageemailadmin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'usageemailmember@superworks.com', password: 'password12345' });
  await usagestore.recordUsageSnapshot(ctx, { userId: member._id, accounts: [{ accountUuid: 'e1', organizationUuid: 'o', label: 'x', fiveHour: 1, sevenDay: 1 }] });
  await ctx.repo.users.updateById(member._id, { emailEnc: 'not-valid-ciphertext' });
  const out = await reporting.usageOverview(ctx, { adminId: admin._id });
  const row = out.rows.find(r => r.accountUuid === 'e1');
  assert.ok(row);
  assert.equal(row.email, null);
});

test('route: POST /usage/snapshot requires auth (401 without a token); a view-scope bearer is refused (no webView)', async () => {
  const ctx = makeCtx();
  const noAuth = await routes.handleRequest(ctx, req('POST', '/usage/snapshot', { body: { accounts: [] } }));
  assert.equal(noAuth.status, 401);

  await makeActiveUser(ctx, { email: 'usagesnapadmin@superworks.com', password: 'password12345', role: 'admin' });
  const viewBearer = await webBearerFor(ctx, 'usagesnapadmin@superworks.com', 'password12345', 'web-dev-usnap');
  const denied = await routes.handleRequest(ctx, req('POST', '/usage/snapshot', {
    headers: { authorization: viewBearer }, body: { accounts: [] },
  }));
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error, 'This session is view-only.');
});

test('route: POST /usage/snapshot stamps userId from the token; GET /usage/me returns the caller\'s own data', async () => {
  const ctx = makeCtx();
  const member = await makeActiveUser(ctx, { email: 'usagemebearermember@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'usagemebearermember@superworks.com', 'password12345', 'dev-usme');

  const snap = await routes.handleRequest(ctx, req('POST', '/usage/snapshot', {
    headers: { authorization: bearer },
    body: { accounts: [{ accountUuid: 'meacct', organizationUuid: 'meorg', label: 'me@x.com', fiveHour: 33, sevenDay: 44, capturedAt: '2026-07-17T00:00:00.000Z' }] },
  }));
  assert.equal(snap.status, 200);
  assert.equal(snap.body.recorded, 1);

  const me = await routes.handleRequest(ctx, req('GET', '/usage/me', { headers: { authorization: bearer } }));
  assert.equal(me.status, 200);
  assert.equal(me.body.accounts.length, 1);
  assert.equal(me.body.accounts[0].accountUuid, 'meacct');
  assert.equal(me.body.accounts[0].label, 'me@x.com');
  assert.equal(me.body.accounts[0].fiveHour, 33);

  const doc = await ctx.repo.usageSnapshots.findById(`${member._id}|meacct::meorg`);
  assert.equal(doc.userId, member._id, 'the doc is stamped with the authenticated caller, never a client-supplied id');
});

test('route: GET /admin/reports/usage — member 403, admin 200, view-scope (web console) 200', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'usageovadmin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'usageovmember@superworks.com', password: 'password12345' });
  await usagestore.recordUsageSnapshot(ctx, { userId: member._id, accounts: [{ accountUuid: 'ov1', organizationUuid: 'o', label: 'ov', fiveHour: 20, sevenDay: 30 }] });
  const adminBearer = await bearerFor(ctx, 'usageovadmin@superworks.com', 'password12345', 'dev-usov-a');
  const memberBearer = await bearerFor(ctx, 'usageovmember@superworks.com', 'password12345', 'dev-usov-m');
  const viewBearer = await webBearerFor(ctx, 'usageovadmin@superworks.com', 'password12345', 'web-dev-usov');

  const denied = await routes.handleRequest(ctx, req('GET', '/admin/reports/usage', { headers: { authorization: memberBearer } }));
  assert.equal(denied.status, 403);

  const ok = await routes.handleRequest(ctx, req('GET', '/admin/reports/usage', { headers: { authorization: adminBearer } }));
  assert.equal(ok.status, 200);
  assert.ok(Array.isArray(ok.body.rows));
  assert.ok(ok.body.rows.some(r => r.accountUuid === 'ov1'));

  const viewOk = await routes.handleRequest(ctx, req('GET', '/admin/reports/usage', { headers: { authorization: viewBearer } }));
  assert.equal(viewOk.status, 200, 'the web console (view-scope) is allowed to read this report');
});

test('usage snapshots: verifyAuditChain stays ok:true after usage snapshots; storagePercent still computes (proves separation from the audit ledger)', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'usagechainadmin@superworks.com', password: 'password12345', role: 'admin' });
  await audit.recordEvent(ctx, { eventType: 'login', userId: admin._id });
  await usagestore.recordUsageSnapshot(ctx, { userId: admin._id, accounts: [{ accountUuid: 'chain1', organizationUuid: 'o', label: 'x', fiveHour: 5, sevenDay: 5 }] });
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true, 'usage snapshots never touch the audit hash chain');
  const s = await reporting.storagePercent(ctx, { adminId: admin._id });
  assert.ok(s.percent >= 0, 'storagePercent still computes with usage_snapshots present');
});

// ===========================================================================
// ADMIN CREATE USER — POST /admin/users e2e (admin directly provisions an
// employee: active + verified, no OTP). The generic "view-scope structural"
// test further down (which walks routes.ROUTES) also covers the deny side for
// this route automatically since it carries no webView flag.
// ===========================================================================

test('admin/users/http: POST /admin/users creates an active+verified member for an admin caller (201)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'cuadmin@superworks.com', password: 'password12345', role: 'admin' });
  const adminBearer = await bearerFor(ctx, 'cuadmin@superworks.com', 'password12345', 'dev-cu');

  const res = await routes.handleRequest(ctx, req('POST', '/admin/users', {
    headers: { authorization: adminBearer },
    body: { email: 'newemp@superworks.com', password: 'password12345' },
  }));
  assert.equal(res.status, 201);
  assert.ok(res.body.userId);
  assert.equal(res.body.role, 'member');
  assert.equal(res.body.status, 'active');

  const login = await auth.login(ctx, { email: 'newemp@superworks.com', password: 'password12345', deviceId: 'newemp-dev' });
  assert.ok(login.accessToken, 'new employee can log in immediately');
});

test('admin/users/http: a member bearer is refused 403', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'cuadmin2@superworks.com', password: 'password12345', role: 'admin' });
  await makeActiveUser(ctx, { email: 'cumember@superworks.com', password: 'password12345' });
  const memberBearer = await bearerFor(ctx, 'cumember@superworks.com', 'password12345', 'dev-cum');

  const res = await routes.handleRequest(ctx, req('POST', '/admin/users', {
    headers: { authorization: memberBearer },
    body: { email: 'blocked@superworks.com', password: 'password12345' },
  }));
  assert.equal(res.status, 403);
  assert.equal(await users.findUserByEmail(ctx, 'blocked@superworks.com'), null);
});

test('admin/users/http: a view-scope (web console) bearer is refused 403 view-only — mutation route carries no webView flag', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'cuadmin3@superworks.com', password: 'password12345', role: 'admin' });
  const viewBearer = await webBearerFor(ctx, 'cuadmin3@superworks.com', 'password12345', 'web-dev-cu');

  const res = await routes.handleRequest(ctx, req('POST', '/admin/users', {
    headers: { authorization: viewBearer },
    body: { email: 'viewblocked@superworks.com', password: 'password12345' },
  }));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'This session is view-only.');
  assert.equal(await users.findUserByEmail(ctx, 'viewblocked@superworks.com'), null, 'the handler never ran');
});

test('admin/users/http: the newly created user appears in the usersDirectory feed the Users tab reads', async () => {
  const ctx = makeCtx();
  const bossUser = await makeActiveUser(ctx, { email: 'cuadmin4@superworks.com', password: 'password12345', role: 'admin' });
  const adminBearer = await bearerFor(ctx, 'cuadmin4@superworks.com', 'password12345', 'dev-cu4');

  const res = await routes.handleRequest(ctx, req('POST', '/admin/users', {
    headers: { authorization: adminBearer },
    body: { email: 'directoryemp@superworks.com', password: 'password12345', importEnabled: true },
  }));
  assert.equal(res.status, 201);

  const dir = await reporting.usersDirectory(ctx, { adminId: bossUser._id });
  const m = dir.users.find((u) => u.userId === res.body.userId);
  assert.ok(m, 'the new employee appears in the directory');
  assert.equal(m.email, 'directoryemp@superworks.com');
  assert.equal(m.status, 'active');
  assert.equal(m.importEnabled, true);
});

// ===========================================================================
// P2 STEP 10 — signed audit export (report signature AND verifyEvents)
// ===========================================================================

test('audit/export: a signed export verifies; tamper, truncation, and reorder are all caught', async () => {
  const ctx = makeCtx();
  for (let i = 0; i < 4; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i, ip: '8.8.8.8' });
  await audit.anchorNow(ctx);
  const { report, signature } = await audit.exportSigned(ctx);
  const opts = { anchorPublicKey: ctx.config.anchorPublicKey, hmacKey: ctx.config.auditHmacKey };
  assert.equal(audit.verifyExport(report, signature, opts).ok, true);
  // Survives JSON transport (dates → ISO strings) unchanged.
  const round = JSON.parse(JSON.stringify(report));
  assert.equal(audit.verifyExport(round, signature, opts).ok, true);
  // Tamper an event → signature no longer matches.
  const tampered = JSON.parse(JSON.stringify(report)); tampered.events[0].userId = 'evil';
  assert.equal(audit.verifyExport(tampered, signature, opts).ok, false);
  // Drop the last event (truncation) → signature fails.
  const trunc = JSON.parse(JSON.stringify(report)); trunc.events.pop();
  assert.equal(audit.verifyExport(trunc, signature, opts).ok, false);
  // Reorder events → signature fails.
  const reordered = JSON.parse(JSON.stringify(report));
  [reordered.events[0], reordered.events[1]] = [reordered.events[1], reordered.events[0]];
  assert.equal(audit.verifyExport(reordered, signature, opts).ok, false);
});

test('audit/export: a from-bound not on an anchor is SNAPPED down so the export still verifies', async () => {
  const ctx = makeCtx();
  for (let i = 0; i < 5; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i });
  await audit.anchorNow(ctx); // anchor @ 5
  ctx.clock.advance(1000);
  for (let i = 5; i < 8; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i }); // 6,7,8
  const events = await ctx.repo.auditEvents.find({});
  const midTs = events.find(e => e.seq === 7).serverTs; // a from-bound mid-chain
  const { report, signature } = await audit.exportSigned(ctx, { from: midTs });
  assert.equal(report.events[0].seq, 6, 'snapped down to the anchor boundary (seq > anchor@5)');
  assert.equal(audit.verifyExport(report, signature, { anchorPublicKey: ctx.config.anchorPublicKey, hmacKey: ctx.config.auditHmacKey }).ok, true);
});

test('audit/export/http: admin can export; a member is refused', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'u1' });
  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', 'password12345', 'dev-a');
  const memberBearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'dev-m');
  const ok = await routes.handleRequest(ctx, req('GET', '/admin/audit/export', { headers: { authorization: adminBearer } }));
  assert.equal(ok.status, 200);
  assert.ok(ok.body.report && ok.body.signature);
  const denied = await routes.handleRequest(ctx, req('GET', '/admin/audit/export', { headers: { authorization: memberBearer } }));
  assert.equal(denied.status, 403);
});

// ===========================================================================
// P2 STEP 11 — anchor domain separation, perm anchors, retention, scheduler
// ===========================================================================

const retention = require('./lib/retention');
const scheduler = require('./lib/scheduler');

test('anchor/domain-sep: an audit anchor transplanted into perm anchors fails perm verification', async () => {
  const ctx = makeCtx();
  await audit.recordEvent(ctx, { eventType: 'login', userId: 'u1' });
  const auditAnchor = await audit.anchorNow(ctx);
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const m = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: m._id, field: 'exportEnabled', value: true });
  await audit.anchorPermsNow(ctx);
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true, 'perm chain verifies with its own anchor');
  // Transplant the audit anchor (signed under the audit domain) into perm anchors.
  await ctx.repo.permAnchors.insert({ seqHigh: auditAnchor.seqHigh, headHash: auditAnchor.headHash, signature: auditAnchor.signature, anchoredAt: auditAnchor.anchoredAt });
  const res = await entitlements.verifyPermissionChain(ctx);
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'anchor_signature_invalid', 'a cross-domain anchor is rejected');
});

test('anchor/perm: tail-truncation of the permission_changes chain is caught by its anchor', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const m = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  for (const f of ['importEnabled', 'exportEnabled']) {
    await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: m._id, field: f, value: true });
  }
  await audit.anchorPermsNow(ctx);
  const entries = await ctx.repo.permissionChanges.find({});
  const anchors = await ctx.repo.permAnchors.find({});
  // Drop the anchored head (tail-truncation) → anchor commits above the retained head.
  const truncated = entries.slice(0, -1);
  const res = audit.verifyEvents(truncated, anchors, { hmacKey: ctx.config.auditHmacKey, anchorPublicKey: ctx.config.anchorPublicKey, domain: audit.PERM_DOMAIN });
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'anchor_ahead_of_head');
});

test('retention: prune deletes the anchored old prefix, retains the tail, which still verifies', async () => {
  const ctx = makeCtx();
  for (let i = 0; i < 5; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i });
  await audit.anchorNow(ctx);                       // anchor @ 5, events aged at t0
  ctx.clock.advance(8 * 24 * 3600e3);               // 8 days later (> 7-day retention)
  for (let i = 5; i < 8; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i }); // 6,7,8 recent
  await audit.anchorNow(ctx);                       // anchor @ 8 recent
  const res = await retention.pruneAnchorAligned(ctx, { events: ctx.repo.auditEvents, anchors: ctx.repo.auditAnchors, retentionDays: 7 });
  assert.equal(res.boundarySeq, 5, 'boundary is the old anchor');
  assert.equal(res.pruned, 5);
  assert.deepEqual((await ctx.repo.auditEvents.find({})).map(e => e.seq), [6, 7, 8], 'delete seq<=5, retain seq>5');
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true, 'retained tail still verifies from the anchor');
});

test('retention: never prunes to empty, and never prunes events younger than the window', async () => {
  // (a) All events old but the only anchor == head → prune nothing (never empty).
  const ctxA = makeCtx();
  for (let i = 0; i < 3; i++) await audit.recordEvent(ctxA, { eventType: 'login', userId: 'u' + i });
  await audit.anchorNow(ctxA); // anchor @ 3 == head
  ctxA.clock.advance(30 * 24 * 3600e3);
  const rA = await retention.pruneAnchorAligned(ctxA, { events: ctxA.repo.auditEvents, anchors: ctxA.repo.auditAnchors, retentionDays: 7 });
  assert.equal(rA.pruned, 0);
  assert.equal((await ctxA.repo.auditEvents.find({})).length, 3);
  assert.equal((await audit.verifyAuditChain(ctxA)).ok, true);
  // (b) Events below an anchor but younger than the window are NOT pruned (no raw-TTL regression).
  const ctxB = makeCtx();
  for (let i = 0; i < 5; i++) await audit.recordEvent(ctxB, { eventType: 'login', userId: 'u' + i });
  await audit.anchorNow(ctxB); // anchor @ 5, fresh
  for (let i = 5; i < 7; i++) await audit.recordEvent(ctxB, { eventType: 'login', userId: 'u' + i });
  await audit.anchorNow(ctxB); // anchor @ 7
  const rB = await retention.pruneAnchorAligned(ctxB, { events: ctxB.repo.auditEvents, anchors: ctxB.repo.auditAnchors, retentionDays: 7 });
  assert.equal(rB.pruned, 0, 'nothing older than 7 days → nothing pruned');
});

test('scheduler: a maintenance tick anchors both chains and prunes the old audit prefix', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  for (let i = 0; i < 4; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i });
  await audit.anchorNow(ctx); // anchor @ 4 (old after advance)
  ctx.clock.advance(8 * 24 * 3600e3);
  for (let i = 4; i < 6; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i }); // 5,6 recent
  const r = await scheduler.runMaintenance(ctx);
  assert.equal(r.auditOk, true);
  assert.equal(r.permOk, true);
  assert.equal(r.prunedAudit.pruned, 4, 'old prefix pruned at the anchor boundary');
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true);
});

test('scheduler: a tampered audit chain fires a CRITICAL chain-verify anomaly and is NOT pruned', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  for (let i = 0; i < 4; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i });
  await audit.anchorNow(ctx);
  ctx.clock.advance(8 * 24 * 3600e3);
  // Simulate a DB-level tamper: verifyAuditChain reads a mutated first row.
  const realFind = ctx.repo.auditEvents.find.bind(ctx.repo.auditEvents);
  ctx.repo.auditEvents.find = async (f) => {
    const rows = await realFind(f);
    if (rows.length && !f.eventType) rows[0] = { ...rows[0], userId: 'tampered' };
    return rows;
  };
  const r = await scheduler.runMaintenance(ctx);
  assert.equal(r.auditOk, false);
  assert.equal(r.prunedAudit.skipped, 'verify_failed', 'a broken chain is NOT pruned (evidence preserved)');
  const alerts = ctx.repo.auditEvents._all().filter(e => e.eventType === 'anomaly' && e.reason === 'chain_verify_failed' && e.severity === 'critical');
  assert.ok(alerts.length >= 1, 'admins are alerted to the tamper');
});

// ===========================================================================
// P2 REVIEW FIXES — confirmed adversarial-review findings
// ===========================================================================

const watermarkLib = require('./lib/watermark');

test('review/fix: a deviceId cannot be hijacked across users; poll leaks nothing (finding #1)', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const a = await makeActiveUser(ctx, { email: 'a@superworks.com', password: 'password12345' });
  const b = await makeActiveUser(ctx, { email: 'b@superworks.com', password: 'password12345' });
  // A registers dev-1; admin enqueues a wipe for it.
  await auth.login(ctx, { email: 'a@superworks.com', password: 'password12345', deviceId: 'dev-1', ip: '8.8.8.8' });
  const cmd = await commandsLib.enqueueCommand(ctx, { adminId: admin._id, deviceId: 'dev-1', type: 'wipe_claude_creds' });
  // B logs in REUSING dev-1 → must NOT take over A's device; a conflict anomaly fires.
  await auth.login(ctx, { email: 'b@superworks.com', password: 'password12345', deviceId: 'dev-1', ip: '8.8.8.8' });
  assert.equal((await ctx.repo.devices.findById('dev-1')).userId, a._id, "A's device ownership is not overwritten by B");
  assert.ok((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'device_ownership_conflict' })).length >= 1);
  // B cannot poll A's device (403) and A's command is untouched.
  await assert.rejects(() => commandsLib.pollCommands(ctx, { userId: b._id, deviceId: 'dev-1' }), (e) => e.status === 403);
  assert.equal((await ctx.repo.commands.findById(cmd.commandId)).status, 'pending', "A's command was neither seen nor transitioned by B");
});

test('review/fix: a stationary device switching networks (same country) does NOT fire impossible-travel (finding #2)', async () => {
  const ctx = makeCtx({ geo: geoByIp({
    '1.1.1.1': { country: 'US', lat: 37.77, lon: -122.41, asn: 'AS-home' },   // home Wi-Fi
    '2.2.2.2': { country: 'US', lat: 40.71, lon: -74.0, asn: 'AS-carrier' },  // cellular (carrier gateway city)
  }) });
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await makeActiveUser(ctx, { email: 'mob@superworks.com', password: 'password12345' });
  await auth.login(ctx, { email: 'mob@superworks.com', password: 'password12345', deviceId: 'phone', ip: '1.1.1.1' });
  ctx.clock.advance(10 * 60 * 1000);
  await auth.login(ctx, { email: 'mob@superworks.com', password: 'password12345', deviceId: 'phone', ip: '2.2.2.2' });
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'impossible_travel' })).length, 0,
    'a same-country network handoff must not spam a critical alert');
});

test('review/fix: concurrent identical watermark imports dedupe to one row, no 500 (finding #3)', async () => {
  const ctx = makeCtx();
  const results = await Promise.allSettled(Array.from({ length: 6 }, () =>
    watermarkLib.recordImport(ctx, { watermarkId: 'wm-1', userId: 'u1', deviceId: 'd1', ip: '7.7.7.7', fileSha256: 'f1' })));
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 6, 'no call rejects (no 500)');
  assert.equal((await ctx.repo.watermarkImports.find({ watermarkId: 'wm-1' })).length, 1, 'exactly one tracer row');
});

test('review/fix: fail-open logs are redacted — a driver error cannot leak Mongo credentials (finding #4)', async () => {
  const logs = [];
  const leakyMailer = { sent: [], async send() { throw new Error('connect failed mongodb+srv://appuser:s3cr3tPASS@cluster0.mongodb.net/db'); } };
  const ctx = makeCtx({ mailer: leakyMailer, logger: { info() {}, error: (m) => logs.push(m) } });
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await anomaly.emit(ctx, { severity: 'warn', reason: 'new_device', dedupeKey: 'nd1' }); // mailer throws → fail-open log
  assert.ok(logs.length >= 1, 'the failure is logged');
  assert.ok(!logs.some(l => String(l).includes('s3cr3tPASS')), 'credentials must be redacted from fail-open logs');
});

// ===========================================================================
// CLIENT TELEMETRY — POST /heartbeat (both public IPs + coarse geo, cross-check)
// ===========================================================================

const PW = 'password12345';

test('heartbeat: stores both public IPs (encrypted) + coarse geo, and writes NO audit row for a routine beat', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: PW });
  await auth.login(ctx, { email: 'm@superworks.com', password: PW, deviceId: 'dev-1', ip: '203.0.113.9' }); // first device
  const auditBefore = (await ctx.repo.auditEvents.find({})).length;
  await presence.recordHeartbeat(ctx, {
    user: { _id: member._id }, deviceId: 'dev-1', observedIp: '203.0.113.9',
    report: {
      ipv4: '203.0.113.9', ipv6: '2001:db8::1',
      geo4: { country: 'US', region: 'CA', city: 'SF', asn: 'AS1' },
      geo6: { country: 'US', region: 'CA', city: 'SF', asn: 'AS1' },
      appVersion: '1.0.0', os: 'win',
    },
  });
  const dev = await ctx.repo.devices.findById('dev-1');
  assert.equal(netip.decryptIp(ctx, dev.lastIpv4Enc, 'device:dev-1'), '203.0.113.9');
  assert.equal(netip.decryptIp(ctx, dev.lastIpv6Enc, 'device:dev-1'), '2001:db8::1');
  assert.deepEqual(dev.lastGeo4, { country: 'US', region: 'CA', city: 'SF', asn: 'AS1' });
  assert.equal(dev.appVersion, '1.0.0');
  assert.ok(!JSON.stringify(dev).includes('203.0.113.9'), 'no plaintext IP stored');
  assert.equal((await ctx.repo.auditEvents.find({})).length, auditBefore, 'a routine beat is storage-lean (no per-beat audit row)');
});

test('heartbeat: cross-check fires ip_mismatch only when the observed IP is not among the reported IPs (deduped)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  const m = await makeActiveUser(ctx, { email: 'm@superworks.com', password: PW });
  await auth.login(ctx, { email: 'm@superworks.com', password: PW, deviceId: 'dev-1', ip: '8.8.8.8' });
  // Matching observed IP → no anomaly.
  await presence.recordHeartbeat(ctx, { user: { _id: m._id }, deviceId: 'dev-1', observedIp: '8.8.8.8', report: { ipv4: '8.8.8.8' } });
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'ip_mismatch' })).length, 0);
  // Observed IP differs from all reported → mismatch anomaly (once, deduped).
  await presence.recordHeartbeat(ctx, { user: { _id: m._id }, deviceId: 'dev-1', observedIp: '9.9.9.9', report: { ipv4: '8.8.8.8' } });
  await presence.recordHeartbeat(ctx, { user: { _id: m._id }, deviceId: 'dev-1', observedIp: '9.9.9.9', report: { ipv4: '8.8.8.8' } });
  assert.equal((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'ip_mismatch' })).length, 1, 'repeated mismatch coalesces');
});

test('heartbeat: a new device and cross-border travel are detected off the reported geo', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  const m = await makeActiveUser(ctx, { email: 't@superworks.com', password: PW });
  await auth.login(ctx, { email: 't@superworks.com', password: PW, deviceId: 'dev-T', ip: '1.1.1.1' });
  // First beat: London.
  await presence.recordHeartbeat(ctx, { user: { _id: m._id }, deviceId: 'dev-T', observedIp: '1.1.1.1', report: { ipv4: '1.1.1.1', geo4: { country: 'GB', lat: 51.5, lon: -0.1, asn: 'AS1' } } });
  ctx.clock.advance(10 * 60 * 1000);
  // Second beat 10 min later: New York → impossible cross-border travel.
  await presence.recordHeartbeat(ctx, { user: { _id: m._id }, deviceId: 'dev-T', observedIp: '2.2.2.2', report: { ipv4: '2.2.2.2', geo4: { country: 'US', lat: 40.7, lon: -74.0, asn: 'AS2' } } });
  assert.ok((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'impossible_travel' })).length >= 1);
  // A heartbeat from a brand-new second device warns.
  await presence.recordHeartbeat(ctx, { user: { _id: m._id }, deviceId: 'dev-T2', observedIp: '3.3.3.3', report: { ipv4: '3.3.3.3' } });
  assert.ok((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'new_device' })).length >= 1);
});

test('heartbeat/http: returns pending commands and requires auth', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  await makeActiveUser(ctx, { email: 'm@superworks.com', password: PW });
  const bearer = await bearerFor(ctx, 'm@superworks.com', PW, 'dev-1'); // creates device dev-1
  const cmd = await commandsLib.enqueueCommand(ctx, { adminId: admin._id, deviceId: 'dev-1', type: 'wipe_claude_creds' });
  const hb = await routes.handleRequest(ctx, req('POST', '/heartbeat', {
    headers: { authorization: bearer }, body: { ipv4: '203.0.113.9', geo4: { country: 'US' } }, ip: '203.0.113.9',
  }));
  assert.equal(hb.status, 200);
  assert.equal(hb.body.commands.length, 1);
  assert.equal(hb.body.commands[0].commandId, cmd.commandId);
  // Unauthenticated heartbeat is refused.
  const noAuth = await routes.handleRequest(ctx, req('POST', '/heartbeat', { body: { ipv4: '203.0.113.9' }, ip: '203.0.113.9' }));
  assert.equal(noAuth.status, 401);
});

test('heartbeat: a deviceId owned by another user is refused (no takeover) → 403', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  const a = await makeActiveUser(ctx, { email: 'a@superworks.com', password: PW });
  await makeActiveUser(ctx, { email: 'b@superworks.com', password: PW });
  await auth.login(ctx, { email: 'a@superworks.com', password: PW, deviceId: 'dev-1', ip: '8.8.8.8' }); // A owns dev-1
  const bLogin = await auth.login(ctx, { email: 'b@superworks.com', password: PW, deviceId: 'dev-1', ip: '8.8.8.8' }); // B reuses it
  const res = await routes.handleRequest(ctx, req('POST', '/heartbeat', {
    headers: { authorization: 'Bearer ' + bLogin.accessToken }, body: { ipv4: '8.8.8.8' }, ip: '8.8.8.8',
  }));
  assert.equal(res.status, 403, 'B cannot heartbeat A\'s device');
  assert.equal((await ctx.repo.devices.findById('dev-1')).userId, a._id, 'ownership not overwritten');
});

test('heartbeat + report: admin device inventory shows BOTH IPv4 and IPv6 + their coarse geo', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  const m = await makeActiveUser(ctx, { email: 'm@superworks.com', password: PW });
  await auth.login(ctx, { email: 'm@superworks.com', password: PW, deviceId: 'dev-1', ip: '203.0.113.9' });
  await presence.recordHeartbeat(ctx, {
    user: { _id: m._id }, deviceId: 'dev-1', observedIp: '203.0.113.9',
    report: {
      ipv4: '203.0.113.9', ipv6: '2001:db8::1',
      geo4: { country: 'US', region: 'CA', city: 'SF', asn: 'AS1' },
      geo6: { country: 'US', region: 'CA', city: 'SF', asn: 'AS6' },
    },
  });
  const inv = await reporting.deviceInventory(ctx, { adminId: admin._id });
  const d = inv.devices.find(x => x.deviceId === 'dev-1');
  assert.equal(d.ipv4, '203.0.113.9');
  assert.equal(d.ipv6, '2001:db8::1');
  assert.equal(d.geo4.asn, 'AS1');
  assert.equal(d.geo6.asn, 'AS6');
});

// ===========================================================================
// TASK 1 — audit auto/reason passthrough + heartbeat monitoringEnabled
// ===========================================================================

test('audit/http: a switch event carries auto+reason into the recorded core; omitted auto stays undefined', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'auto@superworks.com', password: PW });
  const bearer = await bearerFor(ctx, 'auto@superworks.com', PW, 'dev-auto');

  const withAuto = await routes.handleRequest(ctx, req('POST', '/audit/events', {
    headers: { authorization: bearer },
    body: { eventType: 'switch', result: 'allowed', auto: true, reason: 'work Fable weekly hit 92%; support has 40% headroom' },
  }));
  assert.equal(withAuto.status, 200);
  const stored = await ctx.repo.auditEvents.find({ seq: withAuto.body.seq });
  assert.equal(stored.length, 1);
  assert.equal(stored[0].auto, true, 'auto must be carried into the recorded core');
  assert.equal(stored[0].reason, 'work Fable weekly hit 92%; support has 40% headroom');

  const withoutAuto = await routes.handleRequest(ctx, req('POST', '/audit/events', {
    headers: { authorization: bearer },
    body: { eventType: 'switch', result: 'allowed' },
  }));
  assert.equal(withoutAuto.status, 200);
  const stored2 = await ctx.repo.auditEvents.find({ seq: withoutAuto.body.seq });
  assert.equal(stored2.length, 1);
  assert.equal(stored2[0].auto, undefined, 'no auto sent → no auto field on the core');
});

test('heartbeat/http: response carries monitoringEnabled, live from the user record (default true, admin can disable)', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  await makeActiveUser(ctx, { email: 'mon@superworks.com', password: PW });
  const bearer = await bearerFor(ctx, 'mon@superworks.com', PW, 'dev-mon');

  const hb1 = await routes.handleRequest(ctx, req('POST', '/heartbeat', {
    headers: { authorization: bearer }, body: { ipv4: '203.0.113.9' }, ip: '203.0.113.9',
  }));
  assert.equal(hb1.status, 200);
  assert.equal(hb1.body.monitoringEnabled, true, 'default is on for a managed tool');
  assert.ok(Array.isArray(hb1.body.commands), 'existing commands shape is unchanged');

  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', PW, 'dev-a');
  const target = await users.findUserByEmail(ctx, 'mon@superworks.com');
  await routes.handleRequest(ctx, req('POST', '/admin/monitoring', {
    headers: { authorization: adminBearer }, body: { targetUserId: target._id, enabled: false },
  }));

  const hb2 = await routes.handleRequest(ctx, req('POST', '/heartbeat', {
    headers: { authorization: bearer }, body: { ipv4: '203.0.113.9' }, ip: '203.0.113.9',
  }));
  assert.equal(hb2.status, 200);
  assert.equal(hb2.body.monitoringEnabled, false, 'reflects the admin-disabled flag on the next heartbeat');
});

// ===========================================================================
// TASK 8 — per-PC encrypted Claude-cred copy (admin-only, server-key-encrypted)
// ===========================================================================

test('devices/claude-cred: upload stores an encrypted blob — no plaintext at rest', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  await makeActiveUser(ctx, { email: 'cc1@superworks.com', password: PW });
  const bearer = await bearerFor(ctx, 'cc1@superworks.com', PW, 'dev-cc1');
  const payload = { profiles: { work: { token: 'sk-ant-plaintext-marker-XYZ' } } };
  const res = await routes.handleRequest(ctx, req('POST', '/devices/claude-cred', {
    headers: { authorization: bearer }, body: { payload },
  }));
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { ok: true });
  const dev = await ctx.repo.devices.findById('dev-cc1');
  assert.ok(dev.claudeCredEnc, 'encrypted blob stored on the device doc');
  assert.ok(!JSON.stringify(dev).includes('sk-ant-plaintext-marker-XYZ'), 'no plaintext token stored at rest');
});

test('devices/claude-cred: invalid payload (not a non-null object) is rejected with 400', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  await makeActiveUser(ctx, { email: 'cc1b@superworks.com', password: PW });
  const bearer = await bearerFor(ctx, 'cc1b@superworks.com', PW, 'dev-cc1b');
  for (const bad of [undefined, null, 'not-an-object', 42, []]) {
    const res = await routes.handleRequest(ctx, req('POST', '/devices/claude-cred', {
      headers: { authorization: bearer }, body: { payload: bad },
    }));
    assert.equal(res.status, 400, `payload ${JSON.stringify(bad)} must be rejected`);
  }
});

test('devices/claude-cred: round-trips through the admin read (decrypts with the record AAD)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  await makeActiveUser(ctx, { email: 'cc2@superworks.com', password: PW });
  const bearer = await bearerFor(ctx, 'cc2@superworks.com', PW, 'dev-cc2');
  const payload = { profiles: { work: { token: 'sk-ant-abc' } }, active: 'work' };
  await routes.handleRequest(ctx, req('POST', '/devices/claude-cred', { headers: { authorization: bearer }, body: { payload } }));
  const out = await devicecreds.readClaudeCred(ctx, { deviceId: 'dev-cc2' });
  assert.deepEqual(out.payload, payload);
  assert.ok(out.claudeCredAt, 'claudeCredAt is stamped');
});

test('devices/claude-cred: admin read is gated — non-admin gets 403 and never sees the payload; admin GET 200s with it', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  await makeActiveUser(ctx, { email: 'cc3@superworks.com', password: PW });
  const memberBearer = await bearerFor(ctx, 'cc3@superworks.com', PW, 'dev-cc3');
  const payload = { profiles: { work: { token: 'sk-ant-def' } } };
  await routes.handleRequest(ctx, req('POST', '/devices/claude-cred', { headers: { authorization: memberBearer }, body: { payload } }));

  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', PW, 'dev-admin-cc3');
  const adminRes = await routes.handleRequest(ctx, req('GET', '/admin/devices/claude-cred', {
    headers: { authorization: adminBearer }, query: { deviceId: 'dev-cc3' },
  }));
  assert.equal(adminRes.status, 200);
  assert.deepEqual(adminRes.body.payload, payload);
  assert.equal(adminRes.body.deviceId, 'dev-cc3');

  const nonAdminRes = await routes.handleRequest(ctx, req('GET', '/admin/devices/claude-cred', {
    headers: { authorization: memberBearer }, query: { deviceId: 'dev-cc3' },
  }));
  assert.equal(nonAdminRes.status, 403);
  assert.equal(JSON.stringify(nonAdminRes.body).includes('sk-ant-def'), false, 'payload never reaches a non-admin response');
});

test('devices/claude-cred: the stored blob is bound to its device — decrypting with the WRONG deviceId AAD fails', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  await makeActiveUser(ctx, { email: 'cc4@superworks.com', password: PW });
  const bearer = await bearerFor(ctx, 'cc4@superworks.com', PW, 'dev-cc4');
  await routes.handleRequest(ctx, req('POST', '/devices/claude-cred', {
    headers: { authorization: bearer }, body: { payload: { profiles: {} } },
  }));
  const dev = await ctx.repo.devices.findById('dev-cc4');
  assert.throws(() => ctx.crypto.decrypt(dev.claudeCredEnc, 'claude:WRONG'),
    /unable to authenticate data|bad decrypt/i, 'decrypting with the wrong record AAD must fail (tamper-evidence)');
  // The correct AAD still works, proving the blob itself is intact — the wrong
  // AAD, not blob corruption, is what caused the failure above.
  assert.doesNotThrow(() => ctx.crypto.decrypt(dev.claudeCredEnc, 'claude:dev-cc4'));
});

test('devices/claude-cred: ownership guard — a second user cannot upload to a deviceId already owned by another user', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  await makeActiveUser(ctx, { email: 'cc5a@superworks.com', password: PW });
  const b = await makeActiveUser(ctx, { email: 'cc5b@superworks.com', password: PW });
  const bearerA = await bearerFor(ctx, 'cc5a@superworks.com', PW, 'dev-cc5'); // A owns dev-cc5 (via presence on login)
  await routes.handleRequest(ctx, req('POST', '/devices/claude-cred', {
    headers: { authorization: bearerA }, body: { payload: { profiles: { owner: 'a' } } },
  }));
  // B logs in reusing the SAME deviceId (mirrors presence's ownership-conflict scenario — login fails open, still issues B a token bound to dev-cc5).
  const bLogin = await auth.login(ctx, { email: 'cc5b@superworks.com', password: PW, deviceId: 'dev-cc5', ip: '8.8.8.8' });
  const res = await routes.handleRequest(ctx, req('POST', '/devices/claude-cred', {
    headers: { authorization: 'Bearer ' + bLogin.accessToken }, body: { payload: { profiles: { owner: 'b' } } },
  }));
  assert.equal(res.status, 409, 'B\'s upload to A\'s device is refused, not silently overwritten');
  const dev = await ctx.repo.devices.findById('dev-cc5');
  assert.equal(dev.userId, (await users.findUserByEmail(ctx, 'cc5a@superworks.com'))._id, 'device ownership unchanged');
  const decrypted = JSON.parse(ctx.crypto.decrypt(dev.claudeCredEnc, 'claude:dev-cc5'));
  assert.deepEqual(decrypted, { profiles: { owner: 'a' } }, 'A\'s cred is not overwritten by B\'s rejected upload');
  void b;
});

test('devices/claude-cred: auth required — unauthenticated upload is 401; admin GET without deviceId is 400', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: PW, role: 'admin' });
  const noAuth = await routes.handleRequest(ctx, req('POST', '/devices/claude-cred', { body: { payload: { a: 1 } } }));
  assert.equal(noAuth.status, 401);

  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', PW, 'dev-admin-cc6');
  const missingId = await routes.handleRequest(ctx, req('GET', '/admin/devices/claude-cred', {
    headers: { authorization: adminBearer }, query: {},
  }));
  assert.equal(missingId.status, 400);
});

// ===========================================================================
// PHASE 5 TASK 1 — scoped tokens ('view' scope) + admin-only web login
// ===========================================================================

test('tokens: signAccessToken with scope:\'view\' puts scope:\'view\' in the payload; absence of the claim means full privilege', () => {
  const ctx = makeCtx();
  const viewToken = tokens.signAccessToken(ctx, { userId: 'u1', role: 'admin', deviceId: 'd', scope: 'view' });
  const viewPayload = tokens.verifyAccessToken(ctx, viewToken);
  assert.equal(viewPayload.scope, 'view');

  // Existing callers never pass `scope` — the claim must be entirely absent
  // (not `undefined`-serialized, not `'full'`), so old tokens and this new
  // code path are indistinguishable to anything that checks for `'view'`.
  const fullToken = tokens.signAccessToken(ctx, { userId: 'u1', role: 'admin', deviceId: 'd' });
  const fullPayload = tokens.verifyAccessToken(ctx, fullToken);
  assert.equal(fullPayload.scope, undefined, 'no scope claim = full privilege (backward compatible)');
  assert.ok(!('scope' in fullPayload), 'the key itself must be absent, not just undefined');
});

test('login: normal /auth/login response and JWT have no scope field (additive-only, unchanged)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'noscope@superworks.com', password: PW });
  const res = await routes.handleRequest(ctx, req('POST', '/auth/login', {
    body: { email: 'noscope@superworks.com', password: PW, deviceId: 'd1' },
  }));
  assert.equal(res.status, 200);
  assert.ok(!('scope' in res.body), 'normal login response must not gain a scope field');
  const payload = tokens.verifyAccessToken(ctx, res.body.accessToken);
  assert.equal(payload.scope, undefined);
});

test('login: the session document has no scope field for a normal login (backward compatible)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'nolscope@superworks.com', password: PW });
  await auth.login(ctx, { email: 'nolscope@superworks.com', password: PW, deviceId: 'dev-nls' });
  const [session] = await ctx.repo.sessions.find({ deviceId: 'dev-nls' });
  assert.equal(session.scope, undefined);
});

test('web-login: admin credentials mint a FULL admin session (no view scope — full-admin web console)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wladmin@superworks.com', password: PW, role: 'admin' });
  const res = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'wladmin@superworks.com', password: PW, deviceId: 'web-dev-1' },
  }));
  assert.equal(res.status, 200);
  assert.ok(res.body.accessToken && res.body.refreshToken);
  assert.equal(res.body.tokenType, 'Bearer');
  assert.equal(res.body.role, 'admin');
  assert.equal(res.body.scope, 'web', "the web console is a full-admin 'web'-scope session (not read-only 'view')");
  assert.ok(res.body.accessExpiresAt && res.body.refreshExpiresAt);
  const payload = tokens.verifyAccessToken(ctx, res.body.accessToken);
  assert.equal(payload.scope, 'web');
  assert.equal(payload.did, 'web-dev-1');
});

test("web-login: the session document persists scope:'web' (full admin, minus webDeny routes)", async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wlsessdoc@superworks.com', password: PW, role: 'admin' });
  await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'wlsessdoc@superworks.com', password: PW, deviceId: 'web-dev-5' },
  }));
  const [session] = await ctx.repo.sessions.find({ deviceId: 'web-dev-5' });
  assert.equal(session.scope, 'web');
});

test('web-login: requires a device id (400), same as /auth/login', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wlnodev@superworks.com', password: PW, role: 'admin' });
  const res = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'wlnodev@superworks.com', password: PW },
  }));
  assert.equal(res.status, 400);
});

test('web-login: a valid member account is refused with 403 "Admin privileges required." — no session/tokens created', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wlmember@superworks.com', password: PW, role: 'member' });
  const res = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'wlmember@superworks.com', password: PW, deviceId: 'web-dev-2' },
  }));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'Admin privileges required.');
  const sessions = await ctx.repo.sessions.find({});
  assert.equal(sessions.length, 0, 'no session/tokens created for a refused web-login');
});

test('web-login: a pending (non-active) admin gets the same uniform 403 "Admin privileges required." (not the pending-specific message)', async () => {
  const ctx = makeCtx();
  await users.createUser(ctx, { email: 'wlpending@superworks.com', password: PW, role: 'admin' }); // stays pending
  const res = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'wlpending@superworks.com', password: PW, deviceId: 'd' },
  }));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'Admin privileges required.');
});

test('web-login: bad password behaves exactly like /auth/login — same generic 401 message', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wlbad@superworks.com', password: PW, role: 'admin' });
  const webRes = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'wlbad@superworks.com', password: 'wrong', deviceId: 'd' },
  }));
  assert.equal(webRes.status, 401);
  assert.equal(webRes.body.error, 'Incorrect email or password.');

  let loginErr;
  await auth.login(ctx, { email: 'ghostwl@superworks.com', password: 'whatever', deviceId: 'd' }).catch(e => { loginErr = e; });
  assert.equal(webRes.body.error, loginErr.message, 'unknown-email and wrong-password must be indistinguishable, same as /auth/login');
});

test('web-login: a non-admin with a WRONG password gets the generic 401, not the 403 admin message (credential check happens first)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wlmemberbad@superworks.com', password: PW, role: 'member' });
  const res = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'wlmemberbad@superworks.com', password: 'wrong', deviceId: 'd' },
  }));
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'Incorrect email or password.');
});

test('web-login: failed attempts count toward the SAME lockout counters as /auth/login', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wllock@superworks.com', password: PW, role: 'admin' });
  for (let i = 0; i < 5; i++) {
    const r = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
      body: { email: 'wllock@superworks.com', password: 'bad', deviceId: 'd' },
    }));
    assert.equal(r.status, 401);
  }
  // Shared lockout state: even the correct password now fails, and it fails on
  // the plain /auth/login endpoint too (not just web-login).
  await assert.rejects(() => auth.login(ctx, { email: 'wllock@superworks.com', password: PW, deviceId: 'd' }), (e) => e.status === 401);
});

test('refresh: a web-login (full admin) refresh token re-mints a full-scope access token', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wlrefresh@superworks.com', password: PW, role: 'admin' });
  const webRes = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'wlrefresh@superworks.com', password: PW, deviceId: 'web-dev-3' },
  }));
  const refreshRes = await routes.handleRequest(ctx, req('POST', '/auth/refresh', {
    body: { refreshToken: webRes.body.refreshToken, deviceId: 'web-dev-3' },
  }));
  assert.equal(refreshRes.status, 200);
  const payload = tokens.verifyAccessToken(ctx, refreshRes.body.accessToken);
  assert.equal(payload.scope, 'web', "refresh re-mints the stored 'web' scope (never client-supplied)");
  const [session] = await ctx.repo.sessions.find({ tokenHash: tokens.hashRefreshToken(refreshRes.body.refreshToken) });
  assert.equal(session.scope, 'web');
});

test('refresh: a client-supplied scope in the request body is ignored — a full-scope session stays full', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wlnoclient@superworks.com', password: PW, role: 'admin' });
  const s1 = await auth.login(ctx, { email: 'wlnoclient@superworks.com', password: PW, deviceId: 'd' }); // normal full-scope login
  const refreshRes = await routes.handleRequest(ctx, req('POST', '/auth/refresh', {
    body: { refreshToken: s1.refreshToken, deviceId: 'd', scope: 'view' },
  }));
  assert.equal(refreshRes.status, 200);
  const payload = tokens.verifyAccessToken(ctx, refreshRes.body.accessToken);
  assert.equal(payload.scope, undefined, 'client-supplied scope must not upgrade/downgrade the session');
});

test('logout: works for a web-login (view-scope) session — refresh token stops working after logout', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'wllogout@superworks.com', password: PW, role: 'admin' });
  const webRes = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'wllogout@superworks.com', password: PW, deviceId: 'web-dev-4' },
  }));
  const logoutRes = await routes.handleRequest(ctx, req('POST', '/auth/logout', {
    body: { refreshToken: webRes.body.refreshToken },
  }));
  assert.equal(logoutRes.status, 200);
  assert.deepEqual(logoutRes.body, { ok: true });
  const refreshRes = await routes.handleRequest(ctx, req('POST', '/auth/refresh', {
    body: { refreshToken: webRes.body.refreshToken, deviceId: 'web-dev-4' },
  }));
  assert.equal(refreshRes.status, 401);
});

// ===========================================================================
// PHASE 5 TASK 2 — view-scope enforcement (default-deny)
// ===========================================================================

const WEBVIEW_ALLOWLIST = new Set([
  'GET /admin/reports/timeline',
  'GET /admin/reports/devices',
  'GET /admin/reports/alerts',
  'GET /admin/reports/storage',
  'GET /admin/reports/transfers',
  'GET /admin/reports/users',
  'GET /admin/reports/usage',
  'GET /watermarks/trace',
  'GET /admin/audit/verify',
  'GET /admin/permission-changes/verify',
  'GET /admin/audit/export',
  'GET /admin/ip-rules',
]);

// STRUCTURAL: iterate the real ROUTES map at test time. For every auth route
// that is NOT flagged webView:true, a view-scope admin bearer must be refused
// with 403 "This session is view-only." — before the handler runs. Because
// this walks routes.ROUTES itself (no hardcoded route list), any route a
// FUTURE task adds is automatically covered on the deny side: forgetting to
// either add webView:true (for a deliberately view-safe read) or leaving it
// off (for anything else) cannot silently regress into an open mutation path.
test('view-scope (structural): every auth:true route without webView:true refuses a view-scope bearer with 403 "This session is view-only."', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'viewstruct@superworks.com', password: PW, role: 'admin' });
  const viewBearer = await webBearerFor(ctx, 'viewstruct@superworks.com', PW, 'web-dev-struct');

  const denied = [];
  const checked = [];
  for (const [key, route] of Object.entries(routes.ROUTES)) {
    if (!route.auth || route.webView) continue;
    const [method, path] = key.split(' ');
    checked.push(key);
    const res = await routes.handleRequest(ctx, req(method, path, { headers: { authorization: viewBearer } }));
    if (res.status === 403 && res.body.error === 'This session is view-only.') denied.push(key);
  }
  // Sanity: this test must actually be exercising a nonzero set of routes —
  // an empty list would make the assertion below vacuously true.
  assert.ok(checked.length > 5, 'expected several non-webView auth routes to check');
  assert.deepEqual(denied, checked, 'every non-webView auth route must be view-only-denied for a view-scope bearer');
});

// The allowlist itself must be exactly the 12 documented routes — catches
// accidental over- or under-tagging of webView:true in routes.js.
test('view-scope: exactly the documented 12 routes carry webView:true', () => {
  const flagged = Object.entries(routes.ROUTES)
    .filter(([, route]) => route.webView === true)
    .map(([key]) => key)
    .sort();
  assert.deepEqual(flagged, [...WEBVIEW_ALLOWLIST].sort());
});

// Excluded on purpose: decrypted Claude credentials must never reach a
// browser session, even though the route is a GET under /admin.
test('view-scope: GET /admin/devices/claude-cred (excluded on purpose) refuses a view-scope bearer with 403 view-only', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'viewcred@superworks.com', password: PW, role: 'admin' });
  const viewBearer = await webBearerFor(ctx, 'viewcred@superworks.com', PW, 'web-dev-cred');
  const res = await routes.handleRequest(ctx, req('GET', '/admin/devices/claude-cred', {
    headers: { authorization: viewBearer }, query: { deviceId: 'dev-1' },
  }));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'This session is view-only.');
});

// Representative mutation proof: the handler genuinely never ran — the target
// user's entitlement is byte-for-byte unchanged and no permission_changes
// ledger entry was appended (the rest of the deny surface relies on the 403 +
// short-circuit position in the pipeline proven by the structural test above).
test('view-scope: POST /admin/entitlements — the handler does not run for a view-scope bearer (no entitlement change, no ledger entry)', async () => {
  const ctx = makeCtx();
  const target = await makeActiveUser(ctx, { email: 'viewtarget@superworks.com', password: PW, role: 'member' });
  await makeActiveUser(ctx, { email: 'viewmut@superworks.com', password: PW, role: 'admin' });
  const viewBearer = await webBearerFor(ctx, 'viewmut@superworks.com', PW, 'web-dev-mut');
  const before = await ctx.repo.users.findById(target._id);

  const res = await routes.handleRequest(ctx, req('POST', '/admin/entitlements', {
    headers: { authorization: viewBearer },
    body: { targetUserId: target._id, field: 'importEnabled', value: true },
  }));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'This session is view-only.');

  const after = await ctx.repo.users.findById(target._id);
  assert.equal(after.importEnabled, before.importEnabled, 'entitlement must be unchanged — handler never ran');
  const changes = await ctx.repo.permissionChanges.find({ targetUserId: target._id });
  assert.equal(changes.length, 0, 'no permission_changes ledger entry — handler never ran');
});

// Second representative mutation proof, on a different lib (commands.js /
// session revocation) — a view-scope bearer must not be able to force-logout
// a user's live sessions.
test('view-scope: POST /admin/commands (force_logout) — the handler does not run for a view-scope bearer (target session survives)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'viewmut2@superworks.com', password: PW, role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'viewvictim@superworks.com', password: PW, role: 'member' });
  const memberSession = await auth.login(ctx, { email: 'viewvictim@superworks.com', password: PW, deviceId: 'victim-dev' });
  const viewBearer = await webBearerFor(ctx, 'viewmut2@superworks.com', PW, 'web-dev-mut2');

  const res = await routes.handleRequest(ctx, req('POST', '/admin/commands', {
    headers: { authorization: viewBearer },
    body: { deviceId: 'victim-dev', type: 'force_logout' },
  }));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'This session is view-only.');

  // The victim's session is still alive — no unilateral effect ran.
  const refreshRes = await routes.handleRequest(ctx, req('POST', '/auth/refresh', {
    body: { refreshToken: memberSession.refreshToken, deviceId: 'victim-dev' },
  }));
  assert.equal(refreshRes.status, 200, 'session must survive — the enqueueCommand handler never ran');
  void member;
});

// POSITIVE spot-checks: a view-scope bearer succeeds on every allowlisted
// route (real data where cheap, so this is a genuine 200, not just "not 403").
test('view-scope: a view-scope bearer succeeds (200) on every one of the 12 allowlisted webView routes', async () => {
  const ctx = makeCtx();
  const adminUser = await makeActiveUser(ctx, { email: 'viewok@superworks.com', password: PW, role: 'admin' });
  const exporter = await makeActiveUser(ctx, { email: 'viewokexp@superworks.com', password: PW });
  await entitlements.setEntitlement(ctx, { adminId: adminUser._id, targetUserId: exporter._id, field: 'exportEnabled', value: true });
  const exporterBearer = await bearerFor(ctx, 'viewokexp@superworks.com', PW, 'dev-viewok-exp');
  const exp = await routes.handleRequest(ctx, req('POST', '/export/authorize', {
    headers: { authorization: exporterBearer, 'idempotency-key': 'viewok-1' },
    body: { fileMeta: { sha256: 'viewok-sha' } }, ip: '8.8.8.8',
  }));
  assert.equal(exp.status, 200);
  const watermarkId = exp.body.watermarkId;

  const viewBearer = await webBearerFor(ctx, 'viewok@superworks.com', PW, 'web-dev-ok');

  const checks = [
    ['GET', '/admin/reports/timeline', {}],
    ['GET', '/admin/reports/devices', {}],
    ['GET', '/admin/reports/alerts', {}],
    ['GET', '/admin/reports/storage', {}],
    ['GET', '/admin/reports/transfers', {}],
    ['GET', '/admin/reports/users', {}],
    ['GET', '/admin/reports/usage', {}],
    ['GET', '/watermarks/trace', { watermarkId }],
    ['GET', '/admin/audit/verify', {}],
    ['GET', '/admin/permission-changes/verify', {}],
    ['GET', '/admin/audit/export', {}],
    ['GET', '/admin/ip-rules', {}],
  ];
  for (const [method, path, query] of checks) {
    const res = await routes.handleRequest(ctx, req(method, path, { headers: { authorization: viewBearer }, query }));
    assert.equal(res.status, 200, `${method} ${path} should succeed (200) for a view-scope bearer; got ${res.status}: ${JSON.stringify(res.body)}`);
  }
});

// REGRESSION: a full-scope (ordinary) admin token behaves exactly as before —
// it can reach both an allowlisted route AND a non-allowlisted mutation route
// (the latter proving webView enforcement never fires for full scope).
test('view-scope: a full-scope admin bearer is unaffected — works on both an allowlisted route and a non-allowlisted mutation route', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'fullscope@superworks.com', password: PW, role: 'admin' });
  const target = await makeActiveUser(ctx, { email: 'fullscopetarget@superworks.com', password: PW, role: 'member' });
  const fullBearer = await bearerFor(ctx, 'fullscope@superworks.com', PW, 'dev-full');

  const reportRes = await routes.handleRequest(ctx, req('GET', '/admin/reports/devices', { headers: { authorization: fullBearer } }));
  assert.equal(reportRes.status, 200);

  const mutateRes = await routes.handleRequest(ctx, req('POST', '/admin/entitlements', {
    headers: { authorization: fullBearer },
    body: { targetUserId: target._id, field: 'importEnabled', value: true },
  }));
  assert.equal(mutateRes.status, 200);
  assert.equal((await ctx.repo.users.findById(target._id)).importEnabled, true, 'full-scope admin mutation must still apply');
});

// ===========================================================================
// PHASE 5 TASK 4 — admin password change (re-auth + audited): POST /auth/change-password
// ===========================================================================

// Route shape: auth:true, admin:true, NO webView — a view-scope (web console)
// bearer must get the generic "This session is view-only." 403 before the
// handler ever runs (also covered by the structural view-scope test above,
// which walks routes.ROUTES automatically — this is the explicit spot-check).
test('change-password: a view-scope bearer is refused 403 view-only (route carries no webView flag)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'cpview@superworks.com', password: PW, role: 'admin' });
  const viewBearer = await webBearerFor(ctx, 'cpview@superworks.com', PW, 'web-dev-cp');

  const res = await routes.handleRequest(ctx, req('POST', '/auth/change-password', {
    headers: { authorization: viewBearer },
    body: { currentPassword: PW, newPassword: 'newpassword123' },
  }));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'This session is view-only.');
});

test('change-password: a member (non-admin) bearer is refused 403 "Admin privileges required."', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'cpmember@superworks.com', password: PW, role: 'member' });
  const memberBearer = await bearerFor(ctx, 'cpmember@superworks.com', PW, 'dev-cp-member');

  const res = await routes.handleRequest(ctx, req('POST', '/auth/change-password', {
    headers: { authorization: memberBearer },
    body: { currentPassword: PW, newPassword: 'newpassword123' },
  }));
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'Admin privileges required.');
});

test('change-password: wrong current password → 401 generic (same message as login); nothing changes', async () => {
  const ctx = makeCtx();
  const adminUser = await makeActiveUser(ctx, { email: 'cpwrong@superworks.com', password: PW, role: 'admin' });
  const bearer = await bearerFor(ctx, 'cpwrong@superworks.com', PW, 'dev-cp-wrong');

  const res = await routes.handleRequest(ctx, req('POST', '/auth/change-password', {
    headers: { authorization: bearer },
    body: { currentPassword: 'totally-wrong', newPassword: 'brandnewpassword1' },
  }));
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'Incorrect email or password.');

  // Old password still works — nothing was rotated.
  const loginRes = await routes.handleRequest(ctx, req('POST', '/auth/login', {
    body: { email: 'cpwrong@superworks.com', password: PW, deviceId: 'dcheck-wrong' },
  }));
  assert.equal(loginRes.status, 200);

  // No ledger/audit entries were written on a failed attempt.
  const pc = await ctx.repo.permissionChanges.find({ targetUserId: adminUser._id, field: 'password_changed' });
  assert.equal(pc.length, 0);
  const events = await ctx.repo.auditEvents.find({ eventType: 'password_changed', userId: adminUser._id });
  assert.equal(events.length, 0);
});

test('change-password: newPassword shorter than MIN_PASSWORD_LEN → 400 with the existing friendly length message', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'cpshort@superworks.com', password: PW, role: 'admin' });
  const bearer = await bearerFor(ctx, 'cpshort@superworks.com', PW, 'dev-cp-short');

  const res = await routes.handleRequest(ctx, req('POST', '/auth/change-password', {
    headers: { authorization: bearer },
    body: { currentPassword: PW, newPassword: 'short1' },
  }));
  assert.equal(res.status, 400);
  assert.equal(res.body.error, `Password must be at least ${users.MIN_PASSWORD_LEN} characters.`);
});

test('change-password: success rotates the hash — old password no longer logs in, new one does; response is 200 {ok:true}', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'cpok@superworks.com', password: PW, role: 'admin' });
  const bearer = await bearerFor(ctx, 'cpok@superworks.com', PW, 'dev-cp-ok');
  const newPw = 'brandnewpassword1';

  const res = await routes.handleRequest(ctx, req('POST', '/auth/change-password', {
    headers: { authorization: bearer },
    body: { currentPassword: PW, newPassword: newPw },
  }));
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { ok: true });

  const oldLogin = await routes.handleRequest(ctx, req('POST', '/auth/login', {
    body: { email: 'cpok@superworks.com', password: PW, deviceId: 'dcheck-old' },
  }));
  assert.equal(oldLogin.status, 401);

  const newLogin = await routes.handleRequest(ctx, req('POST', '/auth/login', {
    body: { email: 'cpok@superworks.com', password: newPw, deviceId: 'dcheck-new' },
  }));
  assert.equal(newLogin.status, 200);
});

test('change-password: revokes every OTHER device\'s session family; the calling device\'s session survives', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'cpsess@superworks.com', password: PW, role: 'admin' });
  // A session on a different device, plus the session actually making the
  // change-password call (deviceId comes from the bearer's `did` claim).
  const otherSession = await auth.login(ctx, { email: 'cpsess@superworks.com', password: PW, deviceId: 'dev-other-1' });
  const callingSession = await auth.login(ctx, { email: 'cpsess@superworks.com', password: PW, deviceId: 'dev-calling' });
  const callingBearer = 'Bearer ' + callingSession.accessToken;

  const res = await routes.handleRequest(ctx, req('POST', '/auth/change-password', {
    headers: { authorization: callingBearer },
    body: { currentPassword: PW, newPassword: 'anothernewpw1' },
  }));
  assert.equal(res.status, 200);

  // The other device's refresh-token family is dead.
  await assert.rejects(
    () => auth.refresh(ctx, { refreshToken: otherSession.refreshToken, deviceId: 'dev-other-1' }),
    (e) => e.status === 401,
  );

  // The calling device's own session survives its own password-change call.
  const refreshed = await auth.refresh(ctx, { refreshToken: callingSession.refreshToken, deviceId: 'dev-calling' });
  assert.ok(refreshed.accessToken, 'the calling device session must survive');
});

test('change-password: audited twice — permission_changes ledger entry (no password material) + audit_events row; both chains verify ok', async () => {
  const ctx = makeCtx();
  const adminUser = await makeActiveUser(ctx, { email: 'cpaudit@superworks.com', password: PW, role: 'admin' });
  const bearer = await bearerFor(ctx, 'cpaudit@superworks.com', PW, 'dev-cp-audit');
  const newPw = 'yetanotherpw1';

  const res = await routes.handleRequest(ctx, req('POST', '/auth/change-password', {
    headers: { authorization: bearer },
    body: { currentPassword: PW, newPassword: newPw },
  }));
  assert.equal(res.status, 200);

  const pc = await ctx.repo.permissionChanges.find({ targetUserId: adminUser._id, field: 'password_changed' });
  assert.equal(pc.length, 1, 'exactly one permission_changes ledger entry');
  assert.equal(pc[0].adminId, adminUser._id);
  assert.equal(pc[0].from, null);
  assert.equal(pc[0].to, null);
  assert.ok(!JSON.stringify(pc[0]).toLowerCase().includes(newPw.toLowerCase()), 'no new-password material in the ledger entry');
  assert.ok(!JSON.stringify(pc[0]).toLowerCase().includes(PW.toLowerCase()), 'no old-password material in the ledger entry');

  const events = await ctx.repo.auditEvents.find({ eventType: 'password_changed', userId: adminUser._id });
  assert.equal(events.length, 1, 'exactly one audit_events row');
  assert.equal(events[0].deviceId, 'dev-cp-audit');
  assert.ok(!JSON.stringify(events[0]).toLowerCase().includes(newPw.toLowerCase()), 'no password material in the audit row');

  const permVerify = await routes.handleRequest(ctx, req('GET', '/admin/permission-changes/verify', { headers: { authorization: bearer } }));
  assert.equal(permVerify.status, 200);
  assert.equal(permVerify.body.ok, true, 'permission_changes chain still verifies after the append');

  const auditVerify = await routes.handleRequest(ctx, req('GET', '/admin/audit/verify', { headers: { authorization: bearer } }));
  assert.equal(auditVerify.status, 200);
  assert.equal(auditVerify.body.ok, true, 'audit_events chain still verifies after the append');
});

test('change-password: 5 wrong-current-password attempts trigger the SAME lockout as /auth/login (shared counters, not a guessing oracle)', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'cplock@superworks.com', password: PW, role: 'admin' });
  const bearer = await bearerFor(ctx, 'cplock@superworks.com', PW, 'dev-cp-lock');

  for (let i = 0; i < 5; i++) {
    const res = await routes.handleRequest(ctx, req('POST', '/auth/change-password', {
      headers: { authorization: bearer },
      body: { currentPassword: 'nope', newPassword: 'irrelevantpw1' },
    }));
    assert.equal(res.status, 401);
  }
  // Locked now — even the CORRECT current password is refused with the same
  // generic 401 (no lockout/existence oracle via this endpoint either).
  const stillLocked = await routes.handleRequest(ctx, req('POST', '/auth/change-password', {
    headers: { authorization: bearer },
    body: { currentPassword: PW, newPassword: 'irrelevantpw1' },
  }));
  assert.equal(stillLocked.status, 401);
  assert.equal(stillLocked.body.error, 'Incorrect email or password.');

  // The SAME lockout blocks ordinary /auth/login too — proving shared counters.
  const loginBlocked = await routes.handleRequest(ctx, req('POST', '/auth/login', {
    body: { email: 'cplock@superworks.com', password: PW, deviceId: 'dcheck-lock' },
  }));
  assert.equal(loginBlocked.status, 401);

  ctx.clock.advance(ctx.config.loginLockout.cooldownMs + 1000);
  const unlocked = await routes.handleRequest(ctx, req('POST', '/auth/login', {
    body: { email: 'cplock@superworks.com', password: PW, deviceId: 'dcheck-lock2' },
  }));
  assert.equal(unlocked.status, 200);
});

// ===========================================================================
// E3 — Smart Alerts: richer alerts feed (email + reasonLabel) + per-user
// alertsEnabled email gate. Additive only: never touches audit.recordEvent /
// CORE_FIELDS / the hash chain — see the anomaly/emit tests below, which
// assert the event is still recorded even when the admin email is skipped.
// ===========================================================================

test('anomaly: REASON_LABELS maps every REASONS value to a non-empty friendly string', () => {
  const { REASONS, REASON_LABELS } = anomaly;
  for (const code of Object.values(REASONS)) {
    assert.equal(typeof REASON_LABELS[code], 'string', `REASON_LABELS missing a label for reason "${code}"`);
    assert.ok(REASON_LABELS[code].length > 0);
  }
});

test('reports/alerts: enriches each row with the affected user\'s email + a friendly reasonLabel', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'alertee@superworks.com', password: 'password12345' });
  await anomaly.emit(ctx, { severity: 'warn', userId: member._id, reason: 'new_device', dedupeKey: 'al1' });
  await anomaly.emit(ctx, { severity: 'critical', userId: member._id, reason: 'impossible_travel', dedupeKey: 'al2' });
  const feed = await reporting.alertsFeed(ctx, { adminId: admin._id });
  const row1 = feed.alerts.find(a => a.reason === 'new_device');
  const row2 = feed.alerts.find(a => a.reason === 'impossible_travel');
  assert.ok(row1 && row2);
  assert.equal(row1.email, 'alertee@superworks.com');
  assert.equal(row1.reasonLabel, 'Sign-in from a new, unrecognized device');
  assert.equal(row2.email, 'alertee@superworks.com');
  assert.equal(row2.reasonLabel, 'Impossible travel between two locations');
  assert.equal(row1.alertsMuted, false, 'alertsEnabled defaults true, so the alert was not muted');
});

test('reports/alerts: an unmapped or null reason falls back to the raw string (or null), never throws', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await audit.recordEvent(ctx, { eventType: 'anomaly', severity: 'warn', reason: 'some_unmapped_reason' });
  await audit.recordEvent(ctx, { eventType: 'anomaly', severity: 'warn', reason: null });
  const feed = await reporting.alertsFeed(ctx, { adminId: admin._id });
  const unmapped = feed.alerts.find(a => a.reason === 'some_unmapped_reason');
  assert.ok(unmapped);
  assert.equal(unmapped.reasonLabel, 'some_unmapped_reason');
  const nullReason = feed.alerts.find(a => a.reason === null);
  assert.ok(nullReason);
  assert.equal(nullReason.reasonLabel, null);
});

test('reports/alerts: email is null (not thrown) when the alert\'s userId cannot be resolved to a user doc', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await anomaly.emit(ctx, { severity: 'warn', userId: 'ghost-user-id', reason: 'new_device', dedupeKey: 'ghost1' });
  const feed = await reporting.alertsFeed(ctx, { adminId: admin._id });
  const row = feed.alerts.find(a => a.userId === 'ghost-user-id');
  assert.ok(row);
  assert.equal(row.email, null);
});

test('reports/alerts: alertsMuted reflects the affected user\'s alertsEnabled===false flag', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'muted@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'alertsEnabled', value: false });
  await anomaly.emit(ctx, { severity: 'warn', userId: member._id, reason: 'new_device', dedupeKey: 'mut1' });
  const feed = await reporting.alertsFeed(ctx, { adminId: admin._id });
  const row = feed.alerts.find(a => a.userId === member._id);
  assert.ok(row);
  assert.equal(row.alertsMuted, true);
});

test('users: createUser defaults alertsEnabled to true (managed tool, on by default)', async () => {
  const ctx = makeCtx();
  const u = await users.createUser(ctx, { email: 'newalertuser@superworks.com', password: 'password12345' });
  assert.equal(u.alertsEnabled, true);
});

test('entitlements: admin sets alertsEnabled=false; recorded in permission_changes; chain still verifies', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'toggled@superworks.com', password: 'password12345' });
  assert.equal(member.alertsEnabled, true, 'default is on');
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'alertsEnabled', value: false });
  assert.equal((await ctx.repo.users.findById(member._id)).alertsEnabled, false);
  assert.ok((await ctx.repo.permissionChanges.find({ field: 'alertsEnabled' })).length >= 1);
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
});

test('anomaly/emit: suppresses the admin EMAIL when the user\'s alertsEnabled===false, but STILL records the audit event', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'silenced@superworks.com', password: 'password12345' });
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'alertsEnabled', value: false });
  const res = await anomaly.emit(ctx, { severity: 'warn', userId: member._id, reason: 'new_device', dedupeKey: 'silenced1' });
  assert.equal(res.idempotent, false, 'the event was newly recorded');
  assert.equal(ctx.mailer.sent.length, 0, 'no admin email — alerts are disabled for this user');
  const events = await ctx.repo.auditEvents.find({ eventType: 'anomaly', userId: member._id });
  assert.equal(events.length, 1, 'the audit event is still recorded despite the muted email');
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true, 'the audit chain is untouched by the email gate');
});

test('anomaly/emit: still emails when alertsEnabled=true (default) — guards against over-suppression', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'normal@superworks.com', password: 'password12345' });
  await anomaly.emit(ctx, { severity: 'warn', userId: member._id, reason: 'new_device', dedupeKey: 'normal1' });
  assert.equal(ctx.mailer.sent.length, 1);
});

test('anomaly/emit: a userId-less (IP-level) anomaly always emails, regardless of any per-user gate', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  await anomaly.emit(ctx, { severity: 'warn', reason: 'repeated_failed_logins', dedupeKey: 'iplevel1' });
  assert.equal(ctx.mailer.sent.length, 1);
});

test('anomaly/emit: fails open on a user-lookup error — email still sent, emit never throws', async () => {
  const ctx = makeCtx();
  await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'flaky@superworks.com', password: 'password12345' });
  ctx.repo.users.findById = async () => { throw new Error('DB hiccup'); };
  const res = await anomaly.emit(ctx, { severity: 'warn', userId: member._id, reason: 'new_device', dedupeKey: 'flaky1' });
  assert.equal(res.idempotent, false);
  assert.equal(ctx.mailer.sent.length, 1, 'fail-open: alert on doubt');
});

test('route: POST /admin/alerts-enabled — admin toggles a user\'s alertsEnabled; member refused 403; view-scope refused 403', async () => {
  const ctx = makeCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'togglee@superworks.com', password: 'password12345' });
  const adminBearer = await bearerFor(ctx, 'admin@superworks.com', 'password12345', 'dev-a2');
  const res = await routes.handleRequest(ctx, req('POST', '/admin/alerts-enabled', {
    headers: { authorization: adminBearer }, body: { targetUserId: member._id, enabled: false },
  }));
  assert.equal(res.status, 200);
  assert.equal((await ctx.repo.users.findById(member._id)).alertsEnabled, false);
  assert.ok((await ctx.repo.permissionChanges.find({ field: 'alertsEnabled' })).length >= 1);

  // Member cannot toggle alertsEnabled.
  const memberBearer = await bearerFor(ctx, 'togglee@superworks.com', 'password12345', 'dev-m2');
  const denied = await routes.handleRequest(ctx, req('POST', '/admin/alerts-enabled', {
    headers: { authorization: memberBearer }, body: { targetUserId: admin._id, enabled: false },
  }));
  assert.equal(denied.status, 403);

  // View-scope (web console) bearer refused — mutation route carries no webView flag.
  const viewBearer = await webBearerFor(ctx, 'admin@superworks.com', 'password12345', 'web-dev-alerts');
  const viewDenied = await routes.handleRequest(ctx, req('POST', '/admin/alerts-enabled', {
    headers: { authorization: viewBearer }, body: { targetUserId: member._id, enabled: true },
  }));
  assert.equal(viewDenied.status, 403);
  assert.equal(viewDenied.body.error, 'This session is view-only.');
});
