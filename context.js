'use strict';
// Composition root: build the ctx dependency bundle for the real runtime.
// Shared by server.js and cli.js. Tests DO NOT use this (they build ctx from
// the in-memory repo directly), so requiring it never pulls in mongodb.
//
// REPO=memory selects the in-memory repo + console mailer (local demo). Anything
// else uses the Mongo repo + Gmail mailer (production). MAILER=console forces
// the console mailer even against Mongo.

const fs = require('fs');
const path = require('path');
const { loadConfig, parseEnvFile } = require('./lib/config');
const { realClock } = require('./lib/clock');
const { createFieldCrypto } = require('./lib/crypto');
const { createMemoryRepo } = require('./lib/repo');
const { createGmailMailer, createConsoleMailer } = require('./lib/mailer');
const { resolveMx, resolveHost } = require('./lib/dns');
const { resolveGeoProvider } = require('./lib/geo');
const admin = require('./lib/admin');

// Merge backend/.env (if present) under process.env (process.env wins).
function loadEnv() {
  let fileEnv = {};
  try {
    fileEnv = parseEnvFile(fs.readFileSync(path.join(__dirname, '.env'), 'utf8'));
  } catch { /* no .env file — rely on process.env */ }
  return { ...fileEnv, ...process.env };
}

async function createContext(opts = {}) {
  const env = opts.env || loadEnv();
  const config = loadConfig(env);
  const clock = opts.clock || realClock;
  const logger = opts.logger || console;
  const useMemory = (env.REPO || '').toLowerCase() === 'memory';

  let repo;
  // Phase 6 Task 3 — role split: ctx.pruneRepo defaults to whatever the
  // caller injected (test doubles use this), and is otherwise only ever
  // built on the real Mongo path below. It is a Mongo-only concept — the
  // in-memory demo repo has no privileged role to split out, so ctx.pruneRepo
  // stays exactly what was injected (usually undefined) under REPO=memory.
  let pruneRepo = opts.pruneRepo;
  if (opts.repo) repo = opts.repo;
  else if (useMemory) repo = createMemoryRepo();
  else {
    const { createMongoRepo } = require('./mongoRepo'); // lazy: only touches mongodb in prod
    repo = await createMongoRepo(config);
    // When MONGODB_PRUNE_URI is configured, open a SECOND, un-cached Mongo
    // connection under that (delete-capable) role and hand it to
    // ctx.pruneRepo. scheduler.runMaintenance() routes ONLY the
    // deleteBelowSeq() prune calls through it (lib/retention.js); every other
    // read/write — including the anchor + verify steps of the same
    // maintenance tick — stays on the app-role `repo` above. When
    // MONGODB_PRUNE_URI is unset, ctx.pruneRepo stays undefined and
    // runMaintenance falls back to `repo` — today's single-connection
    // behavior, byte-identical.
    if (config.mongoPruneUri && pruneRepo === undefined) {
      pruneRepo = await createMongoRepo(config, { uriOverride: config.mongoPruneUri });
    }
  }

  const wantConsoleMailer = useMemory || (env.MAILER || '').toLowerCase() === 'console';
  const mailer = opts.mailer || (wantConsoleMailer ? createConsoleMailer(logger) : createGmailMailer(config));

  // Fetch is injectable (tests supply a fake); production uses Node's built-in
  // global fetch (available on our required Node >= 20.6, no new dependency).
  const fetchImpl = opts.fetch || globalThis.fetch;

  const ctx = {
    config,
    clock,
    repo,
    pruneRepo, // undefined unless a Mongo REPO + MONGODB_PRUNE_URI (or opts.pruneRepo in tests)
    crypto: createFieldCrypto(config.fieldEncKey, config.blindIndexKey),
    mailer,
    resolveMx,
    resolveHost,
    fetch: fetchImpl,
    // Geo provider is injectable (opts.geo, for tests); otherwise resolved
    // from config.geoProvider (GEO_PROVIDER env var) — 'ip-api' or 'geolite2'
    // wire a real resolver, unset/'none' keeps the fail-closed null resolver
    // until a provider is configured at deploy time.
    geo: opts.geo || resolveGeoProvider(config, { fetch: fetchImpl, log: logger, readerFactory: opts.geoReaderFactory }),
    logger,
  };

  // Dev-only admin seed for a REPO=memory live demo (Phase 5 Task 3). Gated
  // on `useMemory` itself (derived from REPO), NOT on the shape of `repo` —
  // so this is provably inert on the Mongo path regardless of SEED_ADMIN_*
  // being set. ensureSeedAdmin() is itself a no-op unless both env vars are
  // present, so this is also a no-op for a plain `REPO=memory` with no seed
  // credentials configured.
  if (useMemory) {
    await admin.ensureSeedAdmin(ctx);
  }

  return ctx;
}

module.exports = { createContext, loadEnv };
