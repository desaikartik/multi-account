'use strict';
// Phase 6 Task 1 — graceful shutdown + optional in-process TLS.
//
// Runs fully offline: no real sockets, no real cert files. TLS/shutdown
// behavior is exercised with injected fakes ({http, https, fs}, fake
// server/scheduler/repo), exactly like the rest of the suite.
//
// Run:  cd backend && node --test deploy.test.js

const { test } = require('node:test');
const assert = require('node:assert');

const { generateKeys, loadConfig } = require('./lib/config');
const { createServer, shutdown, buildListener } = require('./server');
const geo = require('./lib/geo');
const { makeClock } = require('./lib/clock');
const { createMemoryRepo } = require('./lib/repo');
const { createFieldCrypto } = require('./lib/crypto');
const { createCaptureMailer } = require('./lib/mailer');
const users = require('./lib/users');
const auth = require('./lib/auth');
const access = require('./lib/access');
const routes = require('./routes');
const { createContext } = require('./context');
const audit = require('./lib/audit');
const retention = require('./lib/retention');
const scheduler = require('./lib/scheduler');
const entitlements = require('./lib/entitlements');

// Same fullEnv() shape as backend.test.js — a complete valid env built from
// freshly generated key material.
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

// ---------------------------------------------------------------------------
// config.js: TLS_KEY_FILE / TLS_CERT_FILE parsing + validation
// ---------------------------------------------------------------------------

test('config: tlsKeyFile/tlsCertFile are null when unset', () => {
  const cfg = loadConfig(fullEnv());
  assert.equal(cfg.tlsKeyFile, null);
  assert.equal(cfg.tlsCertFile, null);
});

test('config: tlsKeyFile/tlsCertFile parse when both set', () => {
  const cfg = loadConfig(fullEnv({ TLS_KEY_FILE: 'C:\\certs\\key.pem', TLS_CERT_FILE: 'C:\\certs\\cert.pem' }));
  assert.equal(cfg.tlsKeyFile, 'C:\\certs\\key.pem');
  assert.equal(cfg.tlsCertFile, 'C:\\certs\\cert.pem');
});

test('config: TLS_KEY_FILE set without TLS_CERT_FILE throws naming the missing var', () => {
  assert.throws(
    () => loadConfig(fullEnv({ TLS_KEY_FILE: 'C:\\certs\\key.pem' })),
    /TLS_CERT_FILE/
  );
});

test('config: TLS_CERT_FILE set without TLS_KEY_FILE throws naming the missing var', () => {
  assert.throws(
    () => loadConfig(fullEnv({ TLS_CERT_FILE: 'C:\\certs\\cert.pem' })),
    /TLS_KEY_FILE/
  );
});

// ---------------------------------------------------------------------------
// shutdown(deps): idempotent graceful close
// ---------------------------------------------------------------------------

function fakeDeps() {
  const calls = { serverClose: 0, schedulerStop: 0, repoClose: 0 };
  return {
    calls,
    server: {
      close(cb) { calls.serverClose += 1; cb(); },
    },
    scheduler: {
      stop() { calls.schedulerStop += 1; },
    },
    repo: {
      async close() { calls.repoClose += 1; },
    },
  };
}

test('shutdown: awaits server.close + scheduler.stop + repo.close exactly once, resolves', async () => {
  const deps = fakeDeps();
  await shutdown(deps);
  assert.equal(deps.calls.serverClose, 1);
  assert.equal(deps.calls.schedulerStop, 1);
  assert.equal(deps.calls.repoClose, 1);
});

test('shutdown: calling twice only runs the underlying closers once (idempotent)', async () => {
  const deps = fakeDeps();
  await shutdown(deps);
  await shutdown(deps);
  assert.equal(deps.calls.serverClose, 1);
  assert.equal(deps.calls.schedulerStop, 1);
  assert.equal(deps.calls.repoClose, 1);
});

test('shutdown: tolerates missing scheduler/repo (no scheduler started, memory repo with no close)', async () => {
  const calls = { serverClose: 0 };
  const deps = {
    server: { close(cb) { calls.serverClose += 1; cb(); } },
    scheduler: null,
    repo: {},
  };
  await shutdown(deps);
  assert.equal(calls.serverClose, 1);
});

test('shutdown: concurrent calls (overlapping in-flight) still only close once', async () => {
  const deps = fakeDeps();
  // Slow down server.close to force overlap between two concurrent shutdown() calls.
  deps.server.close = (cb) => { deps.calls.serverClose += 1; setImmediate(cb); };
  const p1 = shutdown(deps);
  const p2 = shutdown(deps);
  await Promise.all([p1, p2]);
  assert.equal(deps.calls.serverClose, 1);
  assert.equal(deps.calls.schedulerStop, 1);
  assert.equal(deps.calls.repoClose, 1);
});

// ---------------------------------------------------------------------------
// buildListener(ctx, {http, https, fs}): picks http vs https based on config
// ---------------------------------------------------------------------------

function fakeHttp() {
  const calls = [];
  return { calls, createServer(...args) { calls.push(args); return { kind: 'http-server' }; } };
}

function fakeHttps() {
  const calls = [];
  return { calls, createServer(...args) { calls.push(args); return { kind: 'https-server' }; } };
}

function fakeFs(files) {
  return {
    readFileSync(path) {
      if (!(path in files)) throw new Error('unexpected readFileSync: ' + path);
      return files[path];
    },
  };
}

test('buildListener: plain http.createServer when TLS files unset (default, byte-identical)', () => {
  const ctx = { config: loadConfig(fullEnv()) };
  const http = fakeHttp();
  const https = fakeHttps();
  const fs = fakeFs({});
  const listener = buildListener(ctx, { http, https, fs });
  assert.equal(http.calls.length, 1);
  assert.equal(https.calls.length, 0);
  assert.equal(listener.kind, 'http-server');
});

test('buildListener: https.createServer with injected key/cert when both TLS files are set', () => {
  const ctx = {
    config: loadConfig(fullEnv({ TLS_KEY_FILE: 'C:\\certs\\key.pem', TLS_CERT_FILE: 'C:\\certs\\cert.pem' })),
  };
  const http = fakeHttp();
  const https = fakeHttps();
  const fs = fakeFs({
    'C:\\certs\\key.pem': 'FAKE-KEY-BYTES',
    'C:\\certs\\cert.pem': 'FAKE-CERT-BYTES',
  });
  const listener = buildListener(ctx, { http, https, fs });
  assert.equal(https.calls.length, 1);
  assert.equal(http.calls.length, 0);
  const [opts] = https.calls[0];
  assert.equal(opts.key, 'FAKE-KEY-BYTES');
  assert.equal(opts.cert, 'FAKE-CERT-BYTES');
  assert.equal(listener.kind, 'https-server');
});

// ---------------------------------------------------------------------------
// createServer(ctx): wires shutdown() with real scheduler.stop/repo.close
// ---------------------------------------------------------------------------

test('createServer: close() awaits server.close + scheduler.stop + repo.close and is idempotent', async () => {
  const calls = { serverClose: 0, schedulerStop: 0, repoClose: 0 };
  const fakeServer = { close(cb) { calls.serverClose += 1; cb(); } };
  const ctx = {
    config: loadConfig(fullEnv()),
    scheduler: { stop() { calls.schedulerStop += 1; } },
    repo: { async close() { calls.repoClose += 1; } },
  };
  const http = { createServer() { return fakeServer; } };
  const https = fakeHttps();
  const fs = fakeFs({});

  const { server, close } = createServer(ctx, { http, https, fs });
  assert.equal(server, fakeServer);

  await close();
  await close();
  assert.equal(calls.serverClose, 1);
  assert.equal(calls.schedulerStop, 1);
  assert.equal(calls.repoClose, 1);
});

test('createServer: close() tolerates ctx with no scheduler and a repo with no close()', async () => {
  const calls = { serverClose: 0 };
  const fakeServer = { close(cb) { calls.serverClose += 1; cb(); } };
  const ctx = { config: loadConfig(fullEnv()), repo: {} }; // no ctx.scheduler
  const http = { createServer() { return fakeServer; } };
  const https = fakeHttps();
  const fs = fakeFs({});

  const { close } = createServer(ctx, { http, https, fs });
  await close();
  assert.equal(calls.serverClose, 1);
});

// ===========================================================================
// Phase 6 Task 2 — geo providers (ip-api + GeoLite2) wired so geo-fence can
// actually resolve a country. Until now ctx.geo defaulted to
// createNullGeoResolver(), so ANY user with a geoFence configured was locked
// out of every authenticated route (403 GEO_UNKNOWN_UNDER_FENCE). These tests
// cover the two real providers, the config.js/context.js wiring, and an
// integration assertion that the fail-closed lockout becomes a genuine
// allow/deny once a real resolver is injected.
// ===========================================================================

// A fetch double resolving to a Fetch-API-shaped Response ({ json() }).
function fakeFetchJson(data) {
  return async () => ({ json: async () => data });
}

// A MaxMind-reader double: reader.city(ip) → a fixed record.
function fakeReader(record) {
  return { async city() { return record; } };
}

// ---------------------------------------------------------------------------
// config.js: GEO_PROVIDER / GEO_API_URL / GEOLITE2_DB_PATH
// ---------------------------------------------------------------------------

test('config: geoProvider/geoApiUrl/geolite2DbPath default to none/ip-api default url/null', () => {
  const cfg = loadConfig(fullEnv());
  assert.equal(cfg.geoProvider, 'none');
  assert.equal(cfg.geoApiUrl, 'http://ip-api.com/json');
  assert.equal(cfg.geolite2DbPath, null);
});

test('config: GEO_PROVIDER/GEO_API_URL/GEOLITE2_DB_PATH are read from env', () => {
  const cfg = loadConfig(fullEnv({
    GEO_PROVIDER: 'ip-api',
    GEO_API_URL: 'http://mirror.example/json',
    GEOLITE2_DB_PATH: 'C:\\geo\\GeoLite2-City.mmdb',
  }));
  assert.equal(cfg.geoProvider, 'ip-api');
  assert.equal(cfg.geoApiUrl, 'http://mirror.example/json');
  assert.equal(cfg.geolite2DbPath, 'C:\\geo\\GeoLite2-City.mmdb');
});

// ---------------------------------------------------------------------------
// geo.js: createIpApiProvider({fetch, url}) → provider(canonIp)
// ---------------------------------------------------------------------------

test('geo/ip-api: maps a successful ip-api.com response to {country,region,city,asn,lat,lon}', async () => {
  const fetch = fakeFetchJson({
    status: 'success', countryCode: 'US', regionName: 'CA', city: 'SF',
    as: 'AS13335 Cloudflare', lat: 37, lon: -122,
  });
  const provider = geo.createIpApiProvider({ fetch, url: 'http://ip-api.test/json' });
  const rec = await provider('8.8.8.8');
  assert.deepEqual(rec, { country: 'US', region: 'CA', city: 'SF', asn: 'AS13335 Cloudflare', lat: 37, lon: -122 });
});

test('geo/ip-api: fetches "${url}/${canonIp}"', async () => {
  const calls = [];
  const fetch = async (u) => { calls.push(u); return { json: async () => ({ status: 'success', countryCode: 'US' }) }; };
  const provider = geo.createIpApiProvider({ fetch, url: 'http://ip-api.test/json' });
  await provider('8.8.8.8');
  assert.deepEqual(calls, ['http://ip-api.test/json/8.8.8.8']);
});

test('geo/ip-api: status !== "success" returns null', async () => {
  const fetch = fakeFetchJson({ status: 'fail', message: 'invalid query' });
  const provider = geo.createIpApiProvider({ fetch, url: 'http://ip-api.test/json' });
  assert.equal(await provider('8.8.8.8'), null);
});

test('geo/ip-api: a throwing fetch degrades to null (never throws)', async () => {
  const provider = geo.createIpApiProvider({
    fetch: async () => { throw new Error('network down'); },
    url: 'http://ip-api.test/json',
  });
  assert.equal(await provider('8.8.8.8'), null);
});

test('geo/ip-api: a throwing res.json() also degrades to null', async () => {
  const provider = geo.createIpApiProvider({
    fetch: async () => ({ json: async () => { throw new Error('bad json'); } }),
    url: 'http://ip-api.test/json',
  });
  assert.equal(await provider('8.8.8.8'), null);
});

// ---------------------------------------------------------------------------
// geo.js: createGeoResolver(createIpApiProvider(...)) — the wrapper still
// filters private/invalid IPs BEFORE the provider ever runs.
// ---------------------------------------------------------------------------

test('geo/ip-api + createGeoResolver: a private IP is never passed to the provider', async () => {
  let called = false;
  const provider = geo.createIpApiProvider({
    fetch: async () => { called = true; return { json: async () => ({ status: 'success', countryCode: 'US' }) }; },
    url: 'http://ip-api.test/json',
  });
  const resolver = geo.createGeoResolver(provider);
  const rec = await resolver.lookup('10.0.0.1');
  assert.equal(rec, null);
  assert.equal(called, false, 'private IP must short-circuit before the provider runs');
});

test('geo/ip-api + createGeoResolver: a resolvable public IP round-trips through the wrapper', async () => {
  const provider = geo.createIpApiProvider({
    fetch: fakeFetchJson({ status: 'success', countryCode: 'US', regionName: 'CA', city: 'SF', as: 'AS13335 Cloudflare' }),
    url: 'http://ip-api.test/json',
  });
  const resolver = geo.createGeoResolver(provider);
  const rec = await resolver.lookup('8.8.8.8');
  assert.equal(rec.country, 'US');
  assert.equal(rec.asn, 'AS13335 Cloudflare');
});

// ---------------------------------------------------------------------------
// geo.js: createGeoLite2Provider({readerFactory, dbPath}) → provider(canonIp)
// ---------------------------------------------------------------------------

test('geo/geolite2: maps a MaxMind city record to {country,region,city,asn,lat,lon}', async () => {
  const readerFactory = (dbPath) => {
    assert.equal(dbPath, 'C:\\geo\\City.mmdb');
    return fakeReader({
      country: { isoCode: 'GB' },
      subdivisions: [{ isoCode: 'ENG' }],
      city: { names: { en: 'London' } },
      traits: { autonomousSystemNumber: 5089 },
      location: { latitude: 51.5, longitude: -0.1 },
    });
  };
  const provider = geo.createGeoLite2Provider({ readerFactory, dbPath: 'C:\\geo\\City.mmdb' });
  const rec = await provider('8.8.8.8');
  assert.deepEqual(rec, { country: 'GB', region: 'ENG', city: 'London', asn: 'AS5089', lat: 51.5, lon: -0.1 });
});

test('geo/geolite2: a missing reader record returns null', async () => {
  const provider = geo.createGeoLite2Provider({ readerFactory: () => fakeReader(null), dbPath: 'x.mmdb' });
  assert.equal(await provider('8.8.8.8'), null);
});

test('geo/geolite2: no readerFactory throws synchronously (never crashes module load — caught by resolveGeoProvider)', () => {
  assert.throws(() => geo.createGeoLite2Provider({ dbPath: 'x.mmdb' }), /readerFactory/);
});

test('geo/geolite2: a readerFactory that throws (e.g. missing MaxMind lib/db) propagates out of createGeoLite2Provider', () => {
  assert.throws(
    () => geo.createGeoLite2Provider({ readerFactory: () => { throw new Error('mmdb not found'); }, dbPath: 'missing.mmdb' }),
    /mmdb not found/,
  );
});

// ---------------------------------------------------------------------------
// geo.js: resolveGeoProvider(config, {fetch, log, readerFactory}) — selection
// ---------------------------------------------------------------------------

test('geo/resolveGeoProvider: "ip-api" wires createIpApiProvider through createGeoResolver end to end', async () => {
  const fetch = fakeFetchJson({ status: 'success', countryCode: 'US', regionName: 'CA', city: 'SF', as: 'AS13335 Cloudflare' });
  const resolver = geo.resolveGeoProvider({ geoProvider: 'ip-api', geoApiUrl: 'http://ip-api.test/json' }, { fetch });
  const rec = await resolver.lookup('8.8.8.8');
  assert.equal(rec.country, 'US');
  assert.equal(rec.asn, 'AS13335 Cloudflare');
  // Still the same safety wrapper: private IPs never call the provider.
  assert.equal(await resolver.lookup('10.0.0.1'), null);
});

test('geo/resolveGeoProvider: unset config and explicit "none" both always yield null', async () => {
  const unset = geo.resolveGeoProvider({}, {});
  const none = geo.resolveGeoProvider({ geoProvider: 'none' }, {});
  assert.equal(await unset.lookup('8.8.8.8'), null);
  assert.equal(await none.lookup('8.8.8.8'), null);
});

test('geo/resolveGeoProvider: "geolite2" with a working readerFactory wires createGeoLite2Provider end to end', async () => {
  const readerFactory = () => fakeReader({ country: { isoCode: 'DE' } });
  const resolver = geo.resolveGeoProvider({ geoProvider: 'geolite2', geolite2DbPath: 'x.mmdb' }, { readerFactory });
  const rec = await resolver.lookup('8.8.8.8');
  assert.equal(rec.country, 'DE');
});

test('geo/resolveGeoProvider: "geolite2" with no readerFactory falls back to a null resolver and logs a warning', async () => {
  const warnings = [];
  const log = { warn: (m) => warnings.push(m), info: () => {} };
  const resolver = geo.resolveGeoProvider({ geoProvider: 'geolite2', geolite2DbPath: 'x.mmdb' }, { log });
  assert.equal(await resolver.lookup('8.8.8.8'), null);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /geolite2/i);
});

test('geo/resolveGeoProvider: "geolite2" with a throwing readerFactory falls back to a null resolver and logs a warning', async () => {
  const warnings = [];
  const log = { warn: (m) => warnings.push(m), info: () => {} };
  const resolver = geo.resolveGeoProvider(
    { geoProvider: 'geolite2', geolite2DbPath: 'x.mmdb' },
    { log, readerFactory: () => { throw new Error('mmdb missing'); } },
  );
  assert.equal(await resolver.lookup('8.8.8.8'), null);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /mmdb missing/);
});

// ---------------------------------------------------------------------------
// GEO-2 (red-team, Minor): ip-api's default endpoint (GEO_API_URL default,
// config.js) is plaintext HTTP — the free tier has no HTTPS option, so we
// cannot just default to https without breaking it. Defense-in-depth fix:
// resolveGeoProvider now logs a warning at wiring time whenever
// GEO_PROVIDER=ip-api is selected, so the MITM-forgeable-geo-fence risk is
// visible in the server log (and an operator relying on the fence for
// anything security-relevant is pointed at GEO_PROVIDER=geolite2 instead).
// This also closes the earlier-deferred T2 minor: the ip-api branch had no
// log.warn when `fetch` is missing (unlike the geolite2 branch's parallel
// "could not be initialized" warning) — added here too.
// ---------------------------------------------------------------------------

test('geo/resolveGeoProvider: "ip-api" logs a warning that the geo-fence country check runs over plaintext HTTP (MITM-forgeable)', async () => {
  const warnings = [];
  const log = { warn: (m) => warnings.push(m), info: () => {} };
  const fetch = fakeFetchJson({ status: 'success', countryCode: 'US' });
  const resolver = geo.resolveGeoProvider({ geoProvider: 'ip-api', geoApiUrl: 'http://ip-api.test/json' }, { fetch, log });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /plaintext|http/i);
  assert.match(warnings[0], /geolite2/i, 'the warning should point ops at the safer alternative');
  // Defense-in-depth only — behavior/default is unchanged, the resolver still works.
  const rec = await resolver.lookup('8.8.8.8');
  assert.equal(rec.country, 'US');
});

test('geo/resolveGeoProvider: "ip-api" with no injected fetch ALSO warns (parity with the geolite2 missing-readerFactory case) and degrades to null instead of throwing', async () => {
  const warnings = [];
  const log = { warn: (m) => warnings.push(m), info: () => {} };
  const resolver = geo.resolveGeoProvider({ geoProvider: 'ip-api', geoApiUrl: 'http://ip-api.test/json' }, { log });
  assert.equal(warnings.length, 2, 'both the always-on plaintext-HTTP warning and the missing-fetch warning fire');
  assert.match(warnings[1], /fetch/i);
  assert.equal(await resolver.lookup('8.8.8.8'), null, 'no fetch → lookups fail closed to null, never throw');
});

// ---------------------------------------------------------------------------
// context.js: ctx.geo is wired via resolveGeoProvider(config, {fetch, log}),
// with opts.geo still overriding for tests.
// ---------------------------------------------------------------------------

function silentLogger() { return { info() {}, warn() {}, error() {} }; }

test('context: createContext wires ctx.geo via resolveGeoProvider when GEO_PROVIDER=ip-api', async () => {
  const fetch = fakeFetchJson({ status: 'success', countryCode: 'FR' });
  const env = { ...fullEnv(), REPO: 'memory', GEO_PROVIDER: 'ip-api', GEO_API_URL: 'http://ip-api.test/json' };
  const ctx = await createContext({ env, fetch, logger: silentLogger() });
  const rec = await ctx.geo.lookup('8.8.8.8');
  assert.equal(rec.country, 'FR');
});

test('context: createContext defaults ctx.geo to a null resolver when GEO_PROVIDER is unset (fail-closed baseline preserved)', async () => {
  const env = { ...fullEnv(), REPO: 'memory' };
  const ctx = await createContext({ env, logger: silentLogger() });
  assert.equal(await ctx.geo.lookup('8.8.8.8'), null);
});

test('context: opts.geo still overrides resolveGeoProvider (tests can inject a fake resolver)', async () => {
  const env = { ...fullEnv(), REPO: 'memory', GEO_PROVIDER: 'ip-api' };
  const fakeGeoResolver = { async lookup() { return { country: 'ZZ' }; } };
  const ctx = await createContext({ env, geo: fakeGeoResolver, logger: silentLogger() });
  const rec = await ctx.geo.lookup('8.8.8.8');
  assert.equal(rec.country, 'ZZ');
});

// ---------------------------------------------------------------------------
// Integration: a real geo resolver flips the fail-closed geo-fence lockout
// into a genuine allow/deny decision, driven through the actual route
// pipeline (routes.handleRequest → access.enforceUserIp → enforceGeoFence).
// ---------------------------------------------------------------------------

function makeCtx(overrides = {}) {
  const config = loadConfig(fullEnv());
  const clock = makeClock(1_700_000_000_000);
  const repo = createMemoryRepo();
  const crypto = createFieldCrypto(config.fieldEncKey, config.blindIndexKey);
  const resolveMx = async () => [{ exchange: 'mx.test', priority: 10 }];
  const resolveHost = async () => [];
  const mailer = createCaptureMailer();
  const logger = silentLogger();
  return { config, clock, repo, crypto, resolveMx, resolveHost, mailer, logger, geo: geo.createNullGeoResolver(), ...overrides };
}

function req(method, path, opts = {}) {
  const headers = { host: '127.0.0.1', ...(opts.headers || {}) };
  if (method !== 'GET' && headers['content-type'] === undefined && !('content-type' in (opts.headers || {}))) {
    headers['content-type'] = 'application/json';
  }
  return { method, path, query: opts.query || {}, headers, body: opts.body, ip: opts.ip || '1.2.3.4' };
}

async function bearerFor(ctx, email, password, deviceId = 'dev-1') {
  const res = await auth.login(ctx, { email, password, deviceId });
  return 'Bearer ' + res.accessToken;
}

async function makeActiveUser(ctx, { email, password, role = 'member' } = {}) {
  const u = await users.createUser(ctx, { email, password, role });
  await ctx.repo.users.updateById(u._id, { status: 'active', emailVerified: true });
  return ctx.repo.users.findById(u._id);
}

test('integration: resolveGeoProvider("ip-api") turns a matching geo-fence into a real ALLOW where the null resolver would 403', async () => {
  const fetch = fakeFetchJson({ status: 'success', countryCode: 'US', regionName: 'CA', city: 'SF', as: 'AS1' });
  const realGeo = geo.resolveGeoProvider({ geoProvider: 'ip-api', geoApiUrl: 'http://ip-api.test/json' }, { fetch });
  const ctx = makeCtx({ geo: realGeo });
  const adm = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'd');

  await access.setGeoFence(ctx, { adminId: adm._id, targetUserId: member._id, countries: ['US'] });
  const allowed = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(allowed.status, 200, 'a real resolver that resolves the matching country now allows the request');

  // Prove it's a genuine country check (not an "always allow" bug): the same
  // real resolver still denies once the fence no longer matches.
  await access.setGeoFence(ctx, { adminId: adm._id, targetUserId: member._id, countries: ['GB'] });
  const denied = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(denied.status, 403);
  assert.ok((await ctx.repo.auditEvents.find({ eventType: 'anomaly', reason: 'geo_fenced' })).length >= 1);
});

test('integration baseline: with no provider (GEO_PROVIDER unset/"none") the same geo-fenced user stays locked out — the behavior this task fixes', async () => {
  const nullGeo = geo.resolveGeoProvider({ geoProvider: 'none' }, {});
  const ctx = makeCtx({ geo: nullGeo });
  const adm = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });
  const bearer = await bearerFor(ctx, 'm@superworks.com', 'password12345', 'd');
  await access.setGeoFence(ctx, { adminId: adm._id, targetUserId: member._id, countries: ['US'] });
  const res = await routes.handleRequest(ctx, req('GET', '/entitlements/me', { headers: { authorization: bearer }, ip: '8.8.8.8' }));
  assert.equal(res.status, 403, 'no provider configured → fail closed, same as before this task');
});

// ===========================================================================
// Phase 6 Task 3 — split Mongo roles: a separate delete-capable connection for
// the retention prune (deleteBelowSeq is the ONLY delete on the append-only
// audit_events/permission_changes ledgers). Today there is one shared
// connection; this task lets the prune route its deletes through a separate
// privileged repo (ctx.pruneRepo) when MONGODB_PRUNE_URI is configured, with
// UNCHANGED behavior when it is not (back-compat, single connection).
// ===========================================================================

// ---------------------------------------------------------------------------
// config.js: MONGODB_PRUNE_URI → config.mongoPruneUri (nullable, optional)
// ---------------------------------------------------------------------------

test('config: mongoPruneUri defaults to null when MONGODB_PRUNE_URI is unset', () => {
  const cfg = loadConfig(fullEnv());
  assert.equal(cfg.mongoPruneUri, null);
});

test('config: mongoPruneUri is read from MONGODB_PRUNE_URI when set', () => {
  const cfg = loadConfig(fullEnv({ MONGODB_PRUNE_URI: 'mongodb+srv://prune:pw@localhost/?tls=true' }));
  assert.equal(cfg.mongoPruneUri, 'mongodb+srv://prune:pw@localhost/?tls=true');
});

test('config: MONGODB_PRUNE_URI is optional — a config with no other changes still loads fine without it', () => {
  assert.doesNotThrow(() => loadConfig(fullEnv()));
  assert.equal(loadConfig(fullEnv()).mongoPruneUri, null);
});

// ---------------------------------------------------------------------------
// context.js: ctx.pruneRepo wiring. The real Mongo path (MONGODB_PRUNE_URI +
// REPO=mongo) is not exercised here — mongoRepo.js is integration-verified
// against real Mongo at deploy (same convention as the rest of the suite;
// see mongoRepo.js's own header comment) — but the memory-repo guard and the
// opts.pruneRepo injection path are both fully offline-testable and are
// exactly what proves context.js's wiring rule.
// ---------------------------------------------------------------------------

test('context: ctx.pruneRepo stays undefined under REPO=memory even when MONGODB_PRUNE_URI is set (Mongo-only feature)', async () => {
  const env = { ...fullEnv({ MONGODB_PRUNE_URI: 'mongodb+srv://prune:pw@localhost/?tls=true' }), REPO: 'memory' };
  const ctx = await createContext({ env, logger: silentLogger() });
  assert.equal(ctx.pruneRepo, undefined);
});

test('context: opts.repo + opts.pruneRepo are both honored verbatim (injection path used by this suite)', async () => {
  const env = { ...fullEnv(), REPO: 'memory' };
  const repoDouble = createMemoryRepo();
  const pruneRepoDouble = createMemoryRepo();
  const ctx = await createContext({ env, repo: repoDouble, pruneRepo: pruneRepoDouble, logger: silentLogger() });
  assert.equal(ctx.repo, repoDouble);
  assert.equal(ctx.pruneRepo, pruneRepoDouble);
});

test('context: ctx.pruneRepo is undefined when no pruneRepo is injected (back-compat default)', async () => {
  const env = { ...fullEnv(), REPO: 'memory' };
  const ctx = await createContext({ env, logger: silentLogger() });
  assert.equal(ctx.pruneRepo, undefined);
});

// ---------------------------------------------------------------------------
// retention.js: pruneAnchorAligned's new `deleteEvents` param — the delete
// goes to `deleteEvents` when supplied, and falls back to `events` (the read
// handle) when it is not.
// ---------------------------------------------------------------------------

// Wraps a real in-memory collection so deleteBelowSeq() calls are counted on
// THIS handle specifically, while every other method (getHead/findOne/find/
// insert/...) passes straight through to the SAME underlying store — so two
// spies wrapping the same collection stay consistent with each other (a
// delete through one is visible to reads through the other), exactly like two
// Mongo connections pointed at the same database under different roles.
function spyDeleteBelowSeq(collection, calls, key) {
  calls[key] = 0;
  return new Proxy(collection, {
    get(target, prop) {
      if (prop === 'deleteBelowSeq') {
        return async (...args) => { calls[key] += 1; return target.deleteBelowSeq(...args); };
      }
      const v = target[prop];
      return typeof v === 'function' ? v.bind(target) : v;
    },
  });
}

test('retention.pruneAnchorAligned: the delete goes to deleteEvents, never to the events (read) handle, when both are supplied', async () => {
  const ctx = makeCtx();
  for (let i = 0; i < 5; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i });
  await audit.anchorNow(ctx); // anchor @ 5, aged
  ctx.clock.advance(8 * 24 * 3600e3); // > 7-day retention
  for (let i = 5; i < 8; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i }); // 6,7,8 recent
  await audit.anchorNow(ctx); // anchor @ 8

  const calls = {};
  const realEvents = ctx.repo.auditEvents;
  const readHandle = spyDeleteBelowSeq(realEvents, calls, 'readHandle');
  const deleteHandle = spyDeleteBelowSeq(realEvents, calls, 'deleteHandle');

  const res = await retention.pruneAnchorAligned(ctx, {
    events: readHandle, anchors: ctx.repo.auditAnchors, retentionDays: 7, deleteEvents: deleteHandle,
  });
  assert.equal(res.pruned, 5, 'the old prefix was genuinely deleted, not a no-op');
  assert.equal(res.boundarySeq, 5);
  assert.equal(calls.deleteHandle, 1, 'deleteBelowSeq was called exactly once, via deleteEvents');
  assert.equal(calls.readHandle, 0, 'deleteBelowSeq was NEVER called via the read-only events handle');
  assert.deepEqual((await ctx.repo.auditEvents.find({})).map(e => e.seq), [6, 7, 8], 'the underlying store (shared by both handles) is actually pruned');
});

// ---------------------------------------------------------------------------
// scheduler.js: runMaintenance(ctx) role split, end to end. Builds ONE real
// (functioning) in-memory repo as ctx.repo so anchor/verify/audit reads work
// exactly as normal, then wires ctx.pruneRepo as spy-wrapped handles onto the
// SAME underlying auditEvents/permissionChanges collections — so the prune's
// delete is genuinely observable both by (a) the data actually disappearing
// and (b) per-handle call counters proving WHICH connection issued it.
// ---------------------------------------------------------------------------

function makeRoleSplitCtx() {
  const ctx = makeCtx();
  const calls = { app: { auditEvents: 0, permissionChanges: 0 }, prune: { auditEvents: 0, permissionChanges: 0 } };

  const realAuditEvents = ctx.repo.auditEvents;
  const realPermChanges = ctx.repo.permissionChanges;

  // ctx.repo (app role): reads/writes/inserts all still work identically
  // (proxy passthrough); only deleteBelowSeq calls are counted.
  ctx.repo.auditEvents = spyDeleteBelowSeq(realAuditEvents, calls.app, 'auditEvents');
  ctx.repo.permissionChanges = spyDeleteBelowSeq(realPermChanges, calls.app, 'permissionChanges');

  // ctx.pruneRepo: a DIFFERENT handle (different Proxy identity, different
  // call counter) onto the SAME underlying store — the same relationship a
  // real second Mongo connection under a different role has to the same DB.
  ctx.pruneRepo = {
    auditEvents: spyDeleteBelowSeq(realAuditEvents, calls.prune, 'auditEvents'),
    permissionChanges: spyDeleteBelowSeq(realPermChanges, calls.prune, 'permissionChanges'),
  };

  return { ctx, calls };
}

test('scheduler.runMaintenance: with ctx.pruneRepo set, deleteBelowSeq is called via ctx.pruneRepo and NEVER via ctx.repo, on both ledgers', async () => {
  const { ctx, calls } = makeRoleSplitCtx();
  const admin = await makeActiveUser(ctx, { email: 'admin@superworks.com', password: 'password12345', role: 'admin' });
  const member = await makeActiveUser(ctx, { email: 'm@superworks.com', password: 'password12345' });

  // Audit chain: old prefix + recent tail.
  for (let i = 0; i < 4; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i });
  // Permission chain: old prefix + recent tail.
  for (const f of ['importEnabled', 'exportEnabled']) {
    await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: f, value: true });
  }
  await audit.anchorNow(ctx);       // audit anchor @ 4, aged
  await audit.anchorPermsNow(ctx);  // perm anchor @ 2, aged
  ctx.clock.advance(8 * 24 * 3600e3); // > 7-day retention window
  for (let i = 4; i < 6; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i }); // recent audit tail
  await entitlements.setEntitlement(ctx, { adminId: admin._id, targetUserId: member._id, field: 'importEnabled', value: false }); // recent perm tail

  const r = await scheduler.runMaintenance(ctx);

  assert.equal(r.auditOk, true);
  assert.equal(r.permOk, true);
  assert.ok(r.prunedAudit.pruned > 0, 'the audit prefix was genuinely pruned, not a no-op');
  assert.ok(r.prunedPerm.pruned > 0, 'the permission prefix was genuinely pruned, not a no-op');

  assert.equal(calls.prune.auditEvents, 1, 'audit_events delete went through ctx.pruneRepo');
  assert.equal(calls.prune.permissionChanges, 1, 'permission_changes delete went through ctx.pruneRepo');
  assert.equal(calls.app.auditEvents, 0, 'ctx.repo (app role) auditEvents.deleteBelowSeq was NEVER called');
  assert.equal(calls.app.permissionChanges, 0, 'ctx.repo (app role) permissionChanges.deleteBelowSeq was NEVER called');

  // Anchoring + verify reads genuinely went through ctx.repo (the app-role
  // handle) — the retained tail still verifies from that same handle.
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true, 'anchoring/verify reads via ctx.repo produced a still-valid retained tail');
  assert.equal((await entitlements.verifyPermissionChain(ctx)).ok, true);
});

test('scheduler.runMaintenance: with no ctx.pruneRepo, deleteBelowSeq is still called via ctx.repo (back-compat, single connection)', async () => {
  const ctx = makeCtx();
  const calls = { app: {} };
  const realAuditEvents = ctx.repo.auditEvents;
  ctx.repo.auditEvents = spyDeleteBelowSeq(realAuditEvents, calls.app, 'auditEvents');
  assert.equal(ctx.pruneRepo, undefined, 'sanity: no pruneRepo configured');

  for (let i = 0; i < 4; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i });
  await audit.anchorNow(ctx);
  ctx.clock.advance(8 * 24 * 3600e3);
  for (let i = 4; i < 6; i++) await audit.recordEvent(ctx, { eventType: 'login', userId: 'u' + i });

  const r = await scheduler.runMaintenance(ctx);
  assert.equal(r.prunedAudit.pruned, 4, 'still genuinely pruned via ctx.repo when no pruneRepo is configured');
  assert.equal(calls.app.auditEvents, 1, 'the single shared connection (ctx.repo) issued the delete, exactly as before this task');
  assert.equal((await audit.verifyAuditChain(ctx)).ok, true);
});

// ===========================================================================
// Phase 6 Task 4 — serverless (Vercel) adapter: pure functions that translate
// between a Vercel-shaped (req, res) pair and the SAME normalized
// {method, path, query, headers, body, ip} / {status, body, headers} shapes
// server.js's socket adapter produces/consumes (see server.js's `norm` object
// and `send()`), so handleRequest(ctx, req) runs identically on both
// transports. No real sockets are opened anywhere in this section — every
// request/response is a plain fake object, and the round-trip uses an
// in-memory ctx.
// ===========================================================================

const { toNormalizedRequest, writeNormalizedResponse } = require('./lib/serverless');

// ---------------------------------------------------------------------------
// toNormalizedRequest(vreq, {trustProxy, trustedProxyHops})
// ---------------------------------------------------------------------------

test('serverless/toNormalizedRequest: maps method/url/headers/pre-parsed body into the normalized shape', () => {
  const vreq = {
    method: 'POST',
    url: '/auth/login?foo=bar',
    headers: { Host: 'api.example.com', 'Content-Type': 'application/json' },
    body: { email: 'a@example.com', password: 'x' }, // already parsed by the platform
    socket: { remoteAddress: '5.6.7.8' },
  };
  const norm = toNormalizedRequest(vreq, { trustProxy: false, trustedProxyHops: 1 });
  assert.equal(norm.method, 'POST');
  assert.equal(norm.path, '/auth/login');
  assert.deepEqual(norm.query, { foo: 'bar' });
  assert.equal(norm.headers.host, 'api.example.com', 'headers are lowercased, like server.js');
  assert.equal(norm.headers['content-type'], 'application/json');
  assert.deepEqual(norm.body, { email: 'a@example.com', password: 'x' }, 'pre-parsed body used as-is, readJsonBody never called');
  assert.equal(norm.ip, '5.6.7.8', 'trustProxy=false uses the socket peer');
});

test('serverless/toNormalizedRequest: GET/HEAD never carry a body, matching server.js', () => {
  const vreq = { method: 'GET', url: '/health', headers: { host: 'api.example.com' }, body: { should: 'be-ignored' }, socket: { remoteAddress: '1.1.1.1' } };
  const norm = toNormalizedRequest(vreq, {});
  assert.deepEqual(norm.body, {});
});

test('serverless/toNormalizedRequest: an empty/undefined body normalizes to {}', () => {
  const vreq = { method: 'POST', url: '/auth/login', headers: { host: 'h' }, body: undefined, socket: { remoteAddress: '1.1.1.1' } };
  const norm = toNormalizedRequest(vreq, {});
  assert.deepEqual(norm.body, {});
});

test('serverless/toNormalizedRequest: a raw JSON string body (platform did not pre-parse) is parsed like readJsonBody', () => {
  const vreq = { method: 'POST', url: '/auth/login', headers: { host: 'h' }, body: '{"a":1}', socket: { remoteAddress: '1.1.1.1' } };
  const norm = toNormalizedRequest(vreq, {});
  assert.deepEqual(norm.body, { a: 1 });
});

test('serverless/toNormalizedRequest: an invalid JSON string body degrades to {} (never throws), like readJsonBody', () => {
  const vreq = { method: 'POST', url: '/auth/login', headers: { host: 'h' }, body: 'not json', socket: { remoteAddress: '1.1.1.1' } };
  const norm = toNormalizedRequest(vreq, {});
  assert.deepEqual(norm.body, {});
});

// ---------------------------------------------------------------------------
// toNormalizedRequest: ip resolution reuses lib/httpsec.js's resolveClientIp
// — same TRUST_PROXY + hop-count + fail-closed rules as server.js, not
// reimplemented here.
// ---------------------------------------------------------------------------

test('serverless/toNormalizedRequest: trustProxy=false ignores X-Forwarded-For, always uses the socket peer', () => {
  const vreq = { method: 'GET', url: '/health', headers: { host: 'h', 'x-forwarded-for': '9.9.9.9' }, socket: { remoteAddress: '1.1.1.1' } };
  const norm = toNormalizedRequest(vreq, { trustProxy: false, trustedProxyHops: 1 });
  assert.equal(norm.ip, '1.1.1.1');
});

test('serverless/toNormalizedRequest: trustProxy=true takes xff[len-hops] (one trusted hop)', () => {
  const vreq = { method: 'GET', url: '/health', headers: { host: 'h', 'x-forwarded-for': '203.0.113.5, 70.41.3.18' }, socket: { remoteAddress: '1.1.1.1' } };
  const norm = toNormalizedRequest(vreq, { trustProxy: true, trustedProxyHops: 1 });
  assert.equal(norm.ip, '70.41.3.18', 'with one trusted hop, the last (proxy-appended) entry is the real client');
});

test('serverless/toNormalizedRequest: trustProxy=true FAILS CLOSED to the socket peer when XFF is shorter than trustedProxyHops (never list[0])', () => {
  const vreq = { method: 'GET', url: '/health', headers: { host: 'h', 'x-forwarded-for': '203.0.113.5' }, socket: { remoteAddress: '1.1.1.1' } };
  const norm = toNormalizedRequest(vreq, { trustProxy: true, trustedProxyHops: 2 });
  assert.equal(norm.ip, '1.1.1.1', 'XFF has only 1 entry but 2 hops are configured — fail closed, never the spoofable list[0]');
});

test('serverless/toNormalizedRequest: trustProxy=true with no XFF header at all falls back to the socket peer', () => {
  const vreq = { method: 'GET', url: '/health', headers: { host: 'h' }, socket: { remoteAddress: '1.1.1.1' } };
  const norm = toNormalizedRequest(vreq, { trustProxy: true, trustedProxyHops: 1 });
  assert.equal(norm.ip, '1.1.1.1');
});

// ---------------------------------------------------------------------------
// writeNormalizedResponse(vres, result)
// ---------------------------------------------------------------------------

function fakeVercelRes() {
  const r = { headers: {}, statusCode: undefined, body: undefined };
  r.setHeader = (k, v) => { r.headers[k] = v; };
  r.end = (b) => { r.body = b; };
  return r;
}

test('writeNormalizedResponse: sets statusCode, merges headers over a default JSON content-type, and JSON-stringifies an object body', () => {
  const vres = fakeVercelRes();
  writeNormalizedResponse(vres, { status: 201, body: { ok: true }, headers: { 'X-Test': '1' } });
  assert.equal(vres.statusCode, 201);
  assert.equal(vres.headers['Content-Type'], 'application/json');
  assert.equal(vres.headers['X-Test'], '1');
  assert.equal(vres.body, JSON.stringify({ ok: true }));
});

test('writeNormalizedResponse: defaults headers to {} and still sets the JSON content-type when result.headers is absent', () => {
  const vres = fakeVercelRes();
  writeNormalizedResponse(vres, { status: 404, body: { error: 'Not found.' } });
  assert.equal(vres.statusCode, 404);
  assert.equal(vres.headers['Content-Type'], 'application/json');
  assert.equal(vres.body, JSON.stringify({ error: 'Not found.' }));
});

test('writeNormalizedResponse: a string body is written as-is (not double-JSON-encoded)', () => {
  const vres = fakeVercelRes();
  writeNormalizedResponse(vres, { status: 200, body: 'plain text', headers: { 'Content-Type': 'text/plain' } });
  assert.equal(vres.body, 'plain text');
  assert.equal(vres.headers['Content-Type'], 'text/plain');
});

test('writeNormalizedResponse: a Buffer body is written as-is', () => {
  const vres = fakeVercelRes();
  const buf = Buffer.from('binary');
  writeNormalizedResponse(vres, { status: 200, body: buf, headers: {} });
  assert.equal(vres.body, buf);
});

// ---------------------------------------------------------------------------
// Round-trip: build a normalized GET /health via toNormalizedRequest and feed
// it through the REAL handleRequest with an in-memory ctx — proves the
// adapter's output is genuinely handler-compatible, not just shape-matching.
// ---------------------------------------------------------------------------

function makeRoundTripCtx(envOverrides = {}) {
  const config = loadConfig(fullEnv(envOverrides));
  return {
    config,
    clock: makeClock(1_700_000_000_000),
    repo: createMemoryRepo(),
    crypto: createFieldCrypto(config.fieldEncKey, config.blindIndexKey),
    resolveMx: async () => [{ exchange: 'mx.test', priority: 10 }],
    resolveHost: async () => [],
    mailer: createCaptureMailer(),
    logger: silentLogger(),
    geo: geo.createNullGeoResolver(),
  };
}

test('round-trip: toNormalizedRequest output -> real handleRequest -> writeNormalizedResponse, GET /health returns 200', async () => {
  const ctx = makeRoundTripCtx({ ALLOWED_HOSTS: 'switcher.example.com' });

  const vreq = { method: 'GET', url: '/health', headers: { host: 'switcher.example.com' }, socket: { remoteAddress: '203.0.113.9' } };
  const normalized = toNormalizedRequest(vreq, { trustProxy: ctx.config.trustProxy, trustedProxyHops: ctx.config.trustedProxyHops });

  const result = await routes.handleRequest(ctx, normalized);
  assert.equal(result.status, 200);
  assert.equal(result.body.ok, true);

  const vres = fakeVercelRes();
  writeNormalizedResponse(vres, result);
  assert.equal(vres.statusCode, 200);
  assert.deepEqual(JSON.parse(vres.body), result.body);
});

test('round-trip: a Host header NOT in ALLOWED_HOSTS still passes cleanly through the adapter, but handleRequest 403s it (the adapter itself enforces no security)', async () => {
  const ctx = makeRoundTripCtx({ ALLOWED_HOSTS: 'switcher.example.com' });

  const vreq = { method: 'GET', url: '/health', headers: { host: 'evil.example.com' }, socket: { remoteAddress: '203.0.113.9' } };
  const normalized = toNormalizedRequest(vreq, { trustProxy: ctx.config.trustProxy, trustedProxyHops: ctx.config.trustedProxyHops });
  const result = await routes.handleRequest(ctx, normalized);
  assert.equal(result.status, 403);
});
