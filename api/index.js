'use strict';
// Vercel serverless entry point. Adapts each invocation to the SAME
// transport-agnostic handleRequest(ctx, req) pipeline server.js uses, via
// lib/serverless.js — so the exact same handlers + security pipeline run on
// both the Node-http (Render) target and this one.
//
//   backend/vercel.json routes every path to this function.
//
// Warm reuse: ctx is built ONCE per warm instance (module-level cache), the
// same "serverless-safe" pattern mongoRepo.js's cached client already
// documents — a cold start pays the Mongo-connect + key-parsing cost once,
// warm invocations reuse it.
//
// The maintenance scheduler (lib/scheduler.js's setInterval) is NEVER
// started here: a setInterval does not survive between invocations on a
// serverless platform, so it would never fire. This deployment does NOT
// run the retention prune: Vercel Cron Jobs can only invoke an HTTP path
// in the deployment (never a shell command like `node cli.js maintain`),
// ../vercel.json has no `crons` entry, and this repo exposes no maintenance
// endpoint. The prune must instead be run by an EXTERNAL scheduler invoking
// `node cli.js maintain` (the same one-tick maintenance entry point cli.js
// already exposes) — e.g. a CI cron job, a separate always-on host, or the
// Render web service (see ../render.yaml), which keeps SCHEDULER=on instead.

const { createContext } = require('../context');
const { handleRequest } = require('../routes');
const { toNormalizedRequest, writeNormalizedResponse } = require('../lib/serverless');
const { redactSensitive } = require('../lib/errors');

// Module-level warm cache. A Promise (not the resolved ctx) so concurrent
// invocations during a single cold start all await the SAME in-flight build
// instead of racing to build ctx twice. On a build failure, the cache is
// cleared so the NEXT invocation gets a clean retry instead of being wedged
// forever on a poisoned rejected promise.
let ctxPromise = null;

function getWarmContext() {
  if (!ctxPromise) {
    ctxPromise = createContext().catch(err => {
      ctxPromise = null;
      throw err;
    });
  }
  return ctxPromise;
}

module.exports = async function handler(req, res) {
  let ctx;
  try {
    ctx = await getWarmContext();
    const normalized = toNormalizedRequest(req, {
      trustProxy: ctx.config.trustProxy,
      trustedProxyHops: ctx.config.trustedProxyHops,
    });
    // handleRequest never throws (routes.js wraps its whole body in
    // try/catch and returns a {status,body,headers} error response instead)
    // — this outer try/catch mirrors server.js's own defense-in-depth outer
    // catch, guarding cold-start/context-build/adapter failures instead.
    const result = await handleRequest(ctx, normalized);
    writeNormalizedResponse(res, result);
  } catch (err) {
    const logger = (ctx && ctx.logger) || console;
    try {
      const message = redactSensitive('serverless unhandled: ' + (err && err.message));
      if (logger && logger.error) logger.error(message); else console.error(message);
    } catch { /* never let logging itself take down the response */ }
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Something went wrong. Please try again.' }));
  }
};

// Exposed for tests / diagnostics: not part of the Vercel contract.
module.exports.getWarmContext = getWarmContext;
