'use strict';
// Task 3 (Phase 5) — static web-console serving + memory-mode admin seed.
//
// Runs fully offline like backend.test.js: in-memory repo, fixed clock,
// capture mailer. The HTTP-layer tests boot the REAL node:http server
// (backend/server.js's createHttpServer) on an ephemeral port and round-trip
// with the global fetch — no mocked transport.
//
// Run:  cd backend && node --test

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const { makeClock } = require('./lib/clock');
const { generateKeys, loadConfig } = require('./lib/config');
const { createMemoryRepo } = require('./lib/repo');
const { createFieldCrypto } = require('./lib/crypto');
const { createCaptureMailer } = require('./lib/mailer');
const geo = require('./lib/geo');
const { verifyPassword } = require('./lib/passwords');
const users = require('./lib/users');
const admin = require('./lib/admin');
const { webStatic, STATIC_HEADERS, CSP } = require('./lib/webconsole');
const { createHttpServer } = require('./server');
const { createContext } = require('./context');
const routes = require('./routes');

// ---------------------------------------------------------------------------
// Shared test helpers (local to this file — backend.test.js exports none).
// ---------------------------------------------------------------------------

// A complete, valid env built from freshly generated key material (mirrors
// backend.test.js's fullEnv), so both loadConfig() and createContext() get
// everything they require without touching a real .env file or process.env.
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

function makeCtx(envOverrides = {}) {
  const config = loadConfig(fullEnv(envOverrides));
  const clock = makeClock(1_700_000_000_000);
  const repo = createMemoryRepo();
  const crypto = createFieldCrypto(config.fieldEncKey, config.blindIndexKey);
  const mailer = createCaptureMailer();
  const logger = { info() {}, error() {} };
  const geoResolver = geo.createNullGeoResolver();
  const resolveMx = async () => [{ exchange: 'mx.test', priority: 10 }];
  const resolveHost = async () => [];
  return { config, clock, repo, crypto, mailer, resolveMx, resolveHost, logger, geo: geoResolver };
}

// Boots the real http.Server from server.js on an ephemeral loopback port.
// NOTE: this calls createHttpServer(ctx) directly, never server.js's main() —
// so the background scheduler (SCHEDULER=off gate) never starts here and
// there is nothing to unref/stop; the process stays pristine either way.
async function withServer(ctx, fn) {
  const server = createHttpServer(ctx);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base, server); } finally { server.close(); }
}

// ===========================================================================
// webStatic(urlPath) — pure allowlist resolver, no filesystem, no traversal
// ===========================================================================

test('webStatic: /console and /console/ resolve to admin.html (text/html)', () => {
  assert.deepEqual(webStatic('/console'), { file: 'admin.html', contentType: 'text/html; charset=utf-8' });
  assert.deepEqual(webStatic('/console/'), { file: 'admin.html', contentType: 'text/html; charset=utf-8' });
});

test('webStatic: known asset paths resolve with their exact content types', () => {
  assert.deepEqual(webStatic('/console/admin.js'), { file: 'admin.js', contentType: 'text/javascript' });
  assert.deepEqual(webStatic('/console/admin.css'), { file: 'admin.css', contentType: 'text/css' });
  assert.deepEqual(webStatic('/console/adminviews.js'), { file: 'adminviews.js', contentType: 'text/javascript' });
});

test('webStatic: anything not explicitly allowlisted resolves to null (no traversal possible)', () => {
  assert.equal(webStatic('/console/../secret'), null);
  assert.equal(webStatic('/console/x.js'), null);
  assert.equal(webStatic('/consoleX'), null);
  assert.equal(webStatic('/'), null);
  assert.equal(webStatic('/admin.html'), null);
  assert.equal(webStatic('/console/admin.html'), null);
  assert.equal(webStatic(''), null);
  assert.equal(webStatic('/console//admin.js'), null);
});

test('STATIC_HEADERS: exact security header set from the brief, verbatim', () => {
  assert.equal(
    STATIC_HEADERS['Content-Security-Policy'],
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
  assert.equal(STATIC_HEADERS['X-Content-Type-Options'], 'nosniff');
  assert.equal(STATIC_HEADERS['Referrer-Policy'], 'no-referrer');
  assert.equal(STATIC_HEADERS['Cache-Control'], 'no-store');
  assert.equal(CSP, STATIC_HEADERS['Content-Security-Policy']);
});

// ===========================================================================
// Server integration — real HTTP round trip through backend/server.js
// ===========================================================================

test('server: GET /console serves admin.html with every security header', async () => {
  const ctx = makeCtx();
  await withServer(ctx, async base => {
    const res = await fetch(base + '/console');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
    assert.equal(res.headers.get('content-security-policy'), CSP);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(res.headers.get('cache-control'), 'no-store');
    const body = await res.text();
    assert.match(body, /<title>Admin console<\/title>/);
    const onDisk = fs.readFileSync(path.join(__dirname, 'public', 'admin.html'), 'utf8');
    assert.equal(body, onDisk);
  });
});

test('server: GET /console/ (trailing slash) also serves admin.html', async () => {
  const ctx = makeCtx();
  await withServer(ctx, async base => {
    const res = await fetch(base + '/console/');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
  });
});

test('server: GET /console/admin.js serves the placeholder with text/javascript', async () => {
  const ctx = makeCtx();
  await withServer(ctx, async base => {
    const res = await fetch(base + '/console/admin.js');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'text/javascript');
    assert.equal(res.headers.get('cache-control'), 'no-store');
    const body = await res.text();
    const onDisk = fs.readFileSync(path.join(__dirname, 'public', 'admin.js'), 'utf8');
    assert.equal(body, onDisk);
  });
});

test('server: GET /console/admin.css serves the placeholder with text/css', async () => {
  const ctx = makeCtx();
  await withServer(ctx, async base => {
    const res = await fetch(base + '/console/admin.css');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'text/css');
  });
});

test('server: GET /console/adminviews.js serves the UMD placeholder with text/javascript', async () => {
  const ctx = makeCtx();
  await withServer(ctx, async base => {
    const res = await fetch(base + '/console/adminviews.js');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'text/javascript');
    const body = await res.text();
    assert.match(body, /AdminViews/);
  });
});

test('server: an unallowlisted /console/x.js path falls through to the API 404 (JSON, not a file listing)', async () => {
  const ctx = makeCtx();
  await withServer(ctx, async base => {
    const res = await fetch(base + '/console/x.js');
    assert.equal(res.status, 404);
    assert.equal(res.headers.get('content-type'), 'application/json');
    const body = await res.json();
    assert.equal(body.error, 'Not found.');
  });
});

test('server: API routes are completely untouched by the static handler (still JSON)', async () => {
  const ctx = makeCtx();
  await withServer(ctx, async base => {
    const res = await fetch(base + '/health');
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/json');
    const body = await res.json();
    assert.equal(body.ok, true);
  });
});

// ===========================================================================
// Host/Origin — same-origin console page + same-origin API call is not blocked
// ===========================================================================

test('same-origin: browser-shaped GET /console then a same-origin API POST is not origin/Host blocked', async () => {
  const ctx = makeCtx();
  await withServer(ctx, async base => {
    const pageRes = await fetch(base + '/console', {
      headers: { accept: 'text/html,application/xhtml+xml' },
    });
    assert.equal(pageRes.status, 200);

    // Same-origin fetch as a page served from `base` would issue: Origin ===
    // scheme://host:port, which equals the Host header on the wire.
    const apiRes = await fetch(base + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: base },
      body: JSON.stringify({ email: 'nobody@example.com', password: 'wrong-password', deviceId: 'dev-1' }),
    });
    const body = await apiRes.json();
    // Must NOT be the request-security-layer block (403); a 401 (bad
    // credentials, from the auth layer) is the expected, unrelated outcome.
    assert.notEqual(apiRes.status, 403);
    assert.notEqual(body.error, 'Cross-origin requests are not allowed.');
    assert.notEqual(body.error, 'Unexpected Host header.');
    assert.equal(apiRes.status, 401);
    assert.equal(body.error, 'Incorrect email or password.');
  });
});

// ===========================================================================
// Memory-mode admin seed
// ===========================================================================

test('config: loadConfig parses SEED_ADMIN_EMAIL/SEED_ADMIN_PASSWORD when present, null otherwise', () => {
  const withSeed = loadConfig(fullEnv({ SEED_ADMIN_EMAIL: 'seed-admin@example.com', SEED_ADMIN_PASSWORD: 'seed-password-123' }));
  assert.equal(withSeed.seedAdminEmail, 'seed-admin@example.com');
  assert.equal(withSeed.seedAdminPassword, 'seed-password-123');

  const without = loadConfig(fullEnv());
  assert.equal(without.seedAdminEmail, null);
  assert.equal(without.seedAdminPassword, null);
});

test('admin.ensureSeedAdmin: no-op (returns null, creates nothing) when config has no seed credentials', async () => {
  const ctx = makeCtx();
  const res = await admin.ensureSeedAdmin(ctx);
  assert.equal(res, null);
  const admins = await ctx.repo.users.find({ role: 'admin' });
  assert.equal(admins.length, 0);
});

test('admin.ensureSeedAdmin: creates an active, verified admin from the seed credentials', async () => {
  const ctx = makeCtx({ SEED_ADMIN_EMAIL: 'seed-admin@example.com', SEED_ADMIN_PASSWORD: 'seed-password-123' });
  const res = await admin.ensureSeedAdmin(ctx);
  assert.ok(res && res.userId);
  const found = await users.findUserByEmail(ctx, 'seed-admin@example.com');
  assert.ok(found);
  assert.equal(found.role, 'admin');
  assert.equal(found.status, 'active');
  assert.equal(found.emailVerified, true);
  assert.ok(verifyPassword('seed-password-123', found.passwordHash));
});

test('admin.ensureSeedAdmin: idempotent — calling twice never errors and never duplicates', async () => {
  const ctx = makeCtx({ SEED_ADMIN_EMAIL: 'dup-admin@example.com', SEED_ADMIN_PASSWORD: 'seed-password-123' });
  await admin.ensureSeedAdmin(ctx);
  await admin.ensureSeedAdmin(ctx);
  const admins = await ctx.repo.users.find({ role: 'admin' });
  assert.equal(admins.length, 1);
});

test('createContext: REPO=memory + both seed env vars set → an active admin exists after context creation', async () => {
  const env = fullEnv({
    REPO: 'memory',
    SEED_ADMIN_EMAIL: 'seed-admin@example.com',
    SEED_ADMIN_PASSWORD: 'seed-password-123',
  });
  const ctx = await createContext({
    env, clock: makeClock(1_700_000_000_000), logger: { info() {}, error() {} }, mailer: createCaptureMailer(),
  });
  const found = await users.findUserByEmail(ctx, 'seed-admin@example.com');
  assert.ok(found, 'seed admin should exist');
  assert.equal(found.role, 'admin');
  assert.equal(found.status, 'active');
  assert.equal(found.emailVerified, true);
  assert.ok(verifyPassword('seed-password-123', found.passwordHash));
});

test('createContext: REPO=memory but seed vars unset → no admin is seeded', async () => {
  const env = fullEnv({ REPO: 'memory' });
  const ctx = await createContext({
    env, clock: makeClock(1_700_000_000_000), logger: { info() {}, error() {} }, mailer: createCaptureMailer(),
  });
  const admins = await ctx.repo.users.find({ role: 'admin' });
  assert.equal(admins.length, 0);
});

test('createContext: non-memory REPO is inert even with seed vars set — never seeds, never needs Mongo', async () => {
  // REPO left unset ⇒ takes the non-memory branch inside createContext. A
  // repo double is injected via opts.repo so this never touches the real
  // mongodb driver (module is never required); the point of the test is that
  // the seed call is gated on REPO==='memory' itself, not on repo shape.
  const env = fullEnv({
    SEED_ADMIN_EMAIL: 'seed-admin@example.com',
    SEED_ADMIN_PASSWORD: 'seed-password-123',
  });
  const repo = createMemoryRepo();
  const ctx = await createContext({
    env, repo, clock: makeClock(1_700_000_000_000),
    mailer: createCaptureMailer(), logger: { info() {}, error() {} },
  });
  const admins = await ctx.repo.users.find({ role: 'admin' });
  assert.equal(admins.length, 0, 'non-memory context must never invoke the seed path');
});

// ===========================================================================
// Task 7 — web console UI source checks (admin.html / admin.js). These are
// static source-text checks (no DOM/fakedom), in the spirit of the desktop
// suite's csp.test.js: the real enforcement is server-side (route webView
// flags + the strict CSP header, both already covered above and in
// routes.test.js); these tests instead guard that the CLIENT never even
// offers what it cannot do — no inline anything (CSP would block it at
// runtime anyway, but failing fast here is cheaper), no mutation-shaped
// fetch target, and no token ever touching localStorage.
// ===========================================================================

function readPublic(name) {
  return fs.readFileSync(path.join(__dirname, 'public', name), 'utf8');
}

// The exact view-scope allowlist a 'view'-scope bearer token may call
// (backend/routes.js `webView: true` entries) plus the three public auth
// endpoints admin.js is allowed to hit without a token.
const WEB_CONSOLE_PATH_ALLOWLIST = new Set([
  '/auth/web-login', '/auth/refresh', '/auth/logout',
  '/admin/reports/timeline', '/admin/reports/devices', '/admin/reports/alerts',
  '/admin/reports/storage', '/admin/reports/transfers', '/admin/reports/users',
  '/admin/reports/usage',
  '/watermarks/trace',
  '/admin/audit/verify', '/admin/permission-changes/verify',
  '/admin/audit/export', '/admin/ip-rules',
  // Full-admin web console: user-approval mutations (OTP-free signup flow).
  '/admin/users/approve', '/admin/users/reject',
]);

test('admin.html: no inline event handlers, no inline <script> body, no style attributes', () => {
  const html = readPublic('admin.html');
  assert.ok(!/\son\w+\s*=/i.test(html), 'admin.html must not contain inline event-handler attributes (onclick=, onchange=, ...)');
  assert.ok(!/\sstyle\s*=/i.test(html), 'admin.html must not contain inline style="" attributes');
  const scriptTags = html.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || [];
  assert.ok(scriptTags.length >= 2, 'expected at least the two /console/ script tags');
  for (const tag of scriptTags) {
    assert.match(tag, /^<script src="\/console\/[a-zA-Z0-9.]+"><\/script>$/, `script tag must be an empty-bodied external /console/ asset, got: ${tag}`);
  }
});

test('admin.html: loads only /console/-prefixed assets, adminviews.js before admin.js', () => {
  const html = readPublic('admin.html');
  const hrefs = [...html.matchAll(/\shref="([^"]+)"/g)].map(m => m[1]);
  const srcs = [...html.matchAll(/\ssrc="([^"]+)"/g)].map(m => m[1]);
  assert.ok(hrefs.length > 0 && srcs.length > 0, 'expected both an href (stylesheet) and src (scripts) asset');
  for (const url of [...hrefs, ...srcs]) {
    assert.ok(url.startsWith('/console/'), `asset URL is not /console/-prefixed: ${url}`);
  }
  const viewsIdx = html.indexOf('/console/adminviews.js');
  const adminIdx = html.indexOf('/console/admin.js');
  assert.ok(viewsIdx > -1, 'admin.html must load /console/adminviews.js');
  assert.ok(adminIdx > -1, 'admin.html must load /console/admin.js');
  assert.ok(viewsIdx < adminIdx, 'adminviews.js must be loaded before admin.js');
});

test('admin.html: <title>Admin console</title> is preserved (Task 3 server test depends on it)', () => {
  const html = readPublic('admin.html');
  assert.match(html, /<title>Admin console<\/title>/);
});

test('admin.js: localStorage is referenced only for cas-theme / cas-web-device — never a token', () => {
  const src = readPublic('admin.js');
  const localStorageLines = src.split('\n').filter(l => l.includes('localStorage'));
  assert.ok(localStorageLines.length > 0, 'expected admin.js to reference localStorage for the theme + device id');
  for (const line of localStorageLines) {
    assert.ok(/cas-theme|cas-web-device/.test(line), `unexpected/unlabeled localStorage usage: ${line.trim()}`);
  }
  // Belt-and-suspenders: the literal token/session key names must never
  // appear anywhere near "localStorage" as a whole file, and access/refresh
  // tokens must be stored via sessionStorage, never localStorage.
  assert.ok(!/localStorage\.(set|get)Item\(\s*['"]cas-web-(access|refresh)['"]/.test(src), 'a token must never be stored in localStorage');
});

test('admin.js: every /admin, /auth, /watermarks path literal is a known/allowlisted admin path', () => {
  const src = readPublic('admin.js');
  const found = src.match(/\/(?:admin|auth|watermarks)\/[A-Za-z0-9/_-]+/g) || [];
  assert.ok(found.length >= WEB_CONSOLE_PATH_ALLOWLIST.size, 'expected every allowlisted path to appear at least once in admin.js');
  for (const p of found) {
    assert.ok(WEB_CONSOLE_PATH_ALLOWLIST.has(p), `path literal is not on the view-scope allowlist: ${p}`);
  }
  // And the converse: every allowlisted path is actually used somewhere.
  for (const p of WEB_CONSOLE_PATH_ALLOWLIST) {
    assert.ok(found.includes(p), `admin.js never references allowlisted path: ${p}`);
  }
});

test('admin.js: never calls document.write or eval', () => {
  const src = readPublic('admin.js');
  assert.ok(!/document\.write\s*\(/.test(src), 'admin.js must not call document.write');
  assert.ok(!/\beval\s*\(/.test(src), 'admin.js must not call eval');
});

test('admin.js: no inline-handler-shaped assignment (onclick=, onchange=, ...) — delegation only', () => {
  const src = readPublic('admin.js');
  assert.ok(!/\.on(click|change|submit)\s*=/.test(src), 'admin.js must wire events via addEventListener delegation, not .onclick-style assignment');
});

test('adminviews.js on disk is unchanged by Task 7 (Task 6 module is consumed, not modified)', () => {
  const src = readPublic('adminviews.js');
  assert.match(src, /global\.AdminViews = api;/);
});

// ===========================================================================
// F2 — default-deny extension: the new country-deny-list mutation route must
// be refused for a view-scope (web console) bearer, exactly like every other
// non-webView admin mutation route (see backend.test.js's structural
// view-scope test, which also covers this generically since the route
// carries no webView flag — this is the explicit, named spot-check).
// ===========================================================================

function req(method, path, opts = {}) {
  const headers = { host: '127.0.0.1', ...(opts.headers || {}) };
  if (method !== 'GET' && !('content-type' in (opts.headers || {}))) headers['content-type'] = 'application/json';
  return { method, path, query: opts.query || {}, headers, body: opts.body, ip: opts.ip || '1.2.3.4' };
}

test('POST /admin/blocked-countries — a web-login (full admin) bearer CAN mutate: the web console is a full admin console', async () => {
  const ctx = makeCtx();
  const boss = await admin.createAdmin(ctx, { email: 'blkview@example.com', password: 'password12345' });
  const target = await users.createUser(ctx, { email: 'blktarget@example.com', password: 'password12345' });

  const loginRes = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'blkview@example.com', password: 'password12345', deviceId: 'web-dev-blk' },
  }));
  assert.equal(loginRes.status, 200);
  assert.equal(loginRes.body.scope, 'web', "web-login mints a full-admin 'web' session, not a read-only 'view' scope");
  const adminBearer = 'Bearer ' + loginRes.body.accessToken;

  const res = await routes.handleRequest(ctx, req('POST', '/admin/blocked-countries', {
    headers: { authorization: adminBearer },
    body: { targetUserId: target._id, countries: ['US'] },
  }));
  assert.equal(res.status, 200);
  const after = await ctx.repo.users.findById(target._id);
  assert.notEqual(after.blockedCountries, null, 'the full-admin web session applied the change');
  void boss;
});

test('GET /admin/devices/claude-cred — a web-login (scope:web) bearer is DENIED (webDeny), a desktop full session is not', async () => {
  const ctx = makeCtx();
  await admin.createAdmin(ctx, { email: 'credadmin@example.com', password: 'password12345' });

  // Web-login (scope:'web') bearer must be refused — decrypted Claude creds must
  // never reach a browser session, even for a full admin.
  const webRes = await routes.handleRequest(ctx, req('POST', '/auth/web-login', {
    body: { email: 'credadmin@example.com', password: 'password12345', deviceId: 'web-dev-cred2' },
  }));
  assert.equal(webRes.status, 200);
  assert.equal(webRes.body.scope, 'web');
  const webDenied = await routes.handleRequest(ctx, req('GET', '/admin/devices/claude-cred', {
    headers: { authorization: 'Bearer ' + webRes.body.accessToken }, query: { deviceId: 'dev-x' },
  }));
  assert.equal(webDenied.status, 403);
  assert.equal(webDenied.body.error, 'This action is not available in the web console.');

  // A desktop (normal login, no scope) admin session passes the scope gate for
  // the same route (it may then 404 on a missing device, but never the web 403).
  const full = await routes.handleRequest(ctx, req('POST', '/auth/login', {
    body: { email: 'credadmin@example.com', password: 'password12345', deviceId: 'desk-cred' },
  }));
  assert.equal(full.body.scope, undefined, 'a normal login is full (no scope)');
  const deskRes = await routes.handleRequest(ctx, req('GET', '/admin/devices/claude-cred', {
    headers: { authorization: 'Bearer ' + full.body.accessToken }, query: { deviceId: 'dev-x' },
  }));
  assert.notEqual(deskRes.status, 403, 'a desktop full session is not blocked by the web gate');
});
