#!/usr/bin/env node
'use strict';
// Node http server. Adapts sockets → the normalized request that routes.js
// expects, and back. Binds 127.0.0.1 by default (like the local switcher); set
// HOST=0.0.0.0 for a deployed backend behind the platform's TLS proxy.
//
//   REPO=memory MAILER=console node server.js   # local demo (no DB, no Gmail)
//   node server.js                              # production (Atlas + Gmail)

const http = require('http');
const https = require('https');
const fs = require('fs');
const { createContext } = require('./context');
const { handleRequest, APP_NAME, VERSION } = require('./routes');
const { readJsonBody, resolveClientIp } = require('./lib/httpsec');
const { redactSensitive } = require('./lib/errors');
const scheduler = require('./lib/scheduler');
const { webStatic, readStaticFile, STATIC_HEADERS } = require('./lib/webconsole');

function lowercaseHeaders(raw) {
  const out = {};
  for (const [k, v] of Object.entries(raw)) out[k.toLowerCase()] = v;
  return out;
}

function requestListener(ctx) {
  return async (rawReq, res) => {
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
      res.end(JSON.stringify(body));
    };
    try {
      const url = new URL(rawReq.url, 'http://localhost');

      // Admin web-console static files (Phase 5, Addendum B#6): served
      // same-origin, BEFORE the JSON API dispatcher, from an explicit
      // allowlist (backend/lib/webconsole.js) — never a filesystem join of
      // user input, so there is no directory traversal and no listing.
      // Every other route (including unmatched /console/* paths) falls
      // through unchanged to handleRequest, which 404s as JSON like today.
      if (rawReq.method === 'GET') {
        const hit = webStatic(url.pathname);
        if (hit) {
          const bytes = readStaticFile(hit.file);
          res.writeHead(200, { 'Content-Type': hit.contentType, ...STATIC_HEADERS });
          res.end(bytes);
          return;
        }
      }

      const headers = lowercaseHeaders(rawReq.headers);
      let body = {};
      if (rawReq.method !== 'GET' && rawReq.method !== 'HEAD') {
        try {
          body = await readJsonBody(rawReq);
        } catch (e) {
          return send(e.status || 400, { error: e.expose ? e.message : 'Bad request.' });
        }
      }
      const norm = {
        method: rawReq.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
        headers,
        body,
        ip: resolveClientIp(headers, rawReq.socket.remoteAddress, ctx.config.trustProxy, ctx.config.trustedProxyHops),
      };
      const result = await handleRequest(ctx, norm);
      send(result.status, result.body, result.headers);
    } catch (err) {
      if (ctx.logger && ctx.logger.error) ctx.logger.error(redactSensitive('unhandled: ' + (err && err.message)));
      send(500, { error: 'Something went wrong. Please try again.' });
    }
  };
}

function createHttpServer(ctx) {
  return http.createServer(requestListener(ctx));
}

// Build the raw listener: plain http (default — byte-identical to before) or,
// when both config.tlsKeyFile/config.tlsCertFile are set, an in-process https
// server built from those key/cert files. {http, https, fs} are injectable so
// tests can assert which module gets called without any real socket or real
// cert file I/O; real deployments call this with no deps (real modules).
function buildListener(ctx, deps = {}) {
  const httpMod = deps.http || http;
  const httpsMod = deps.https || https;
  const fsMod = deps.fs || fs;
  const listener = requestListener(ctx);
  const { tlsKeyFile, tlsCertFile } = ctx.config;
  if (tlsKeyFile && tlsCertFile) {
    const key = fsMod.readFileSync(tlsKeyFile);
    const cert = fsMod.readFileSync(tlsCertFile);
    return httpsMod.createServer({ key, cert }, listener);
  }
  return httpMod.createServer(listener);
}

// Idempotent graceful shutdown: closes the listening server, stops the
// maintenance scheduler, and closes the repo connection — each exactly once,
// even if shutdown() is invoked more than once for the same deps object
// (e.g. both SIGTERM and SIGINT arrive, or a caller awaits twice).
async function doShutdown({ server, scheduler, repo }) {
  if (server && typeof server.close === 'function') {
    await new Promise((resolve, reject) => {
      server.close(err => (err ? reject(err) : resolve()));
    });
  }
  if (scheduler && typeof scheduler.stop === 'function') scheduler.stop();
  if (repo && typeof repo.close === 'function') await repo.close();
}

function shutdown(deps) {
  if (!deps.__shutdownPromise) {
    deps.__shutdownPromise = doShutdown(deps);
  }
  return deps.__shutdownPromise;
}

// Build the listener and wire graceful shutdown around it. Returns
// { server, close() }. `close()` reads ctx.scheduler/ctx.repo at call time
// (not at construction time) because main() assigns ctx.scheduler AFTER
// creating the server (scheduler.start() runs post-listen), and must still be
// stopped on shutdown. {http, https, fs} pass straight through to
// buildListener for injection in tests.
function createServer(ctx, deps = {}) {
  const server = buildListener(ctx, deps);
  const shutdownDeps = {
    server,
    get scheduler() { return ctx.scheduler; },
    get repo() { return ctx.repo; },
  };
  return { server, close: () => shutdown(shutdownDeps) };
}

async function main() {
  const ctx = await createContext();
  const { server, close } = createServer(ctx);
  const port = ctx.config.port;
  const host = process.env.HOST || '127.0.0.1';
  const scheme = (ctx.config.tlsKeyFile && ctx.config.tlsCertFile) ? 'https' : 'http';
  server.listen(port, host, () => {
    const log = (ctx.logger && ctx.logger.log) ? ctx.logger.log.bind(ctx.logger) : console.log;
    log(`${APP_NAME} v${VERSION} listening on ${scheme}://${host}:${port} (repo=${(process.env.REPO || 'mongo')})`);
  });
  // Persistent-server maintenance: anchor both chains, verify (critical anomaly
  // on tamper), and anchor-aligned-prune past the 7-day window. Opt-out via
  // SCHEDULER=off. On the serverless (Vercel) target this loop does not run —
  // use `node cli.js maintain` on a cron there. In production the prune needs a
  // delete-capable role on the ledgers (kept out of the app's insert+find role).
  if (String(process.env.SCHEDULER || 'on').toLowerCase() !== 'off') {
    ctx.scheduler = scheduler.start(ctx);
  }

  // Graceful shutdown for a Windows-Service or reverse-proxy deployment: stop
  // accepting new connections, stop the maintenance interval, close the repo
  // connection, then exit. Attached ONLY here (never at require-time) so
  // `node --test` never installs process signal handlers.
  let shuttingDown = false;
  const onSignal = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    close()
      .then(() => process.exit(0))
      .catch(err => { console.error(redactSensitive(err && err.message)); process.exit(1); });
  };
  process.on('SIGTERM', onSignal);
  process.on('SIGINT', onSignal);

  return server;
}

if (require.main === module) {
  // SEC-1: same redaction as the shutdown-signal catch above — an unhandled
  // startup failure (e.g. a Mongo connect/URI error) can embed MONGODB_URI
  // WITH credentials, so it must be redacted before it ever reaches stderr.
  main().catch(err => { console.error(redactSensitive(err && err.message)); process.exit(1); });
}

module.exports = { main, createHttpServer, createServer, buildListener, shutdown };
