'use strict';
// Serverless (Vercel) request/response adapter — pure, no I/O, unit-tested in
// isolation. Produces + consumes the exact same normalized shapes
// handleRequest(ctx, req) uses, mirroring server.js's socket adapter:
//   req    = { method, path, query, headers (lowercased), body, ip }
//   result = { status, body, headers }
//
// The one real difference from server.js: a Vercel function receives the
// request body ALREADY consumed by the platform (a parsed object for JSON
// requests, sometimes a raw string, sometimes undefined for an empty body) —
// never as a Node stream to read. So toNormalizedRequest reads req.body
// directly instead of calling lib/httpsec.js's readJsonBody, which expects to
// drain a stream and would hang/misbehave against a pre-parsed request.
//
// IP resolution is NOT reimplemented here — it reuses resolveClientIp from
// lib/httpsec.js verbatim, so the TRUST_PROXY / TRUSTED_PROXY_HOPS /
// fail-closed-to-socket-peer rules stay byte-identical across both
// transports.

const { resolveClientIp } = require('./httpsec');

function lowercaseHeaders(raw) {
  const out = {};
  for (const [k, v] of Object.entries(raw || {})) out[String(k).toLowerCase()] = v;
  return out;
}

// GET/HEAD never carry a body (matches server.js, which never calls
// readJsonBody for those methods and leaves body = {}). For other methods,
// use the platform's already-parsed body when it's an object; if it arrived
// as a raw string, parse it the same way readJsonBody does (empty/invalid ->
// {}, never throws); undefined/null/empty -> {}.
function normalizeBody(vreq, method) {
  if (method === 'GET' || method === 'HEAD') return {};
  const raw = vreq.body;
  if (raw === undefined || raw === null || raw === '') return {};
  if (typeof raw === 'string') {
    try { return JSON.parse(raw); } catch { return {}; }
  }
  return raw; // already parsed by the platform — the common case
}

// vreq: a Vercel-shaped request — { method, url, headers, body, socket? }.
// opts: { trustProxy, trustedProxyHops } — normally ctx.config's values.
function toNormalizedRequest(vreq, opts = {}) {
  const { trustProxy = false, trustedProxyHops = 1 } = opts;
  const method = vreq.method;
  const url = new URL(vreq.url, 'http://localhost');
  const headers = lowercaseHeaders(vreq.headers);
  const body = normalizeBody(vreq, method);
  const socketRemoteAddress = vreq.socket && vreq.socket.remoteAddress;
  const ip = resolveClientIp(headers, socketRemoteAddress, trustProxy, trustedProxyHops);
  return {
    method,
    path: url.pathname,
    query: Object.fromEntries(url.searchParams),
    headers,
    body,
    ip,
  };
}

// vres: a Vercel-shaped response — needs statusCode (settable), setHeader(),
// end() — the same subset of http.ServerResponse Vercel's Node runtime
// provides.
// result: handleRequest's return value, { status, body, headers }.
function writeNormalizedResponse(vres, result) {
  const { status, body, headers } = result || {};
  const outHeaders = { 'Content-Type': 'application/json', ...(headers || {}) };
  const outBody = (typeof body === 'string' || Buffer.isBuffer(body)) ? body : JSON.stringify(body);
  vres.statusCode = status;
  for (const [k, v] of Object.entries(outHeaders)) vres.setHeader(k, v);
  vres.end(outBody);
}

module.exports = { toNormalizedRequest, writeNormalizedResponse };
