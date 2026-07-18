'use strict';
// Request-security primitives, mirroring the existing local switcher's pattern
// (lib/server.js): Host allowlist + Origin match + Content-Type enforcement on
// state-changing methods. Adapted to a configurable host allowlist so the same
// checks work for a deployed backend domain.

// Returns a human string describing why the request is blocked, or null if OK.
// `headers` keys are expected lowercased (Node http normalizes them).
function requestBlockReason(method, headers, allowedHosts) {
  const hostHeader = String(headers.host || '').toLowerCase();
  const host = hostHeader.split(':')[0];
  if (!allowedHosts.includes(host)) return 'Unexpected Host header.';

  if (headers.origin) {
    let origin;
    try { origin = new URL(headers.origin); } catch { return 'Bad Origin header.'; }
    const originHost = origin.hostname.toLowerCase();
    if (!allowedHosts.includes(originHost)) return 'Cross-origin requests are not allowed.';
    if (origin.host.toLowerCase() !== hostHeader) return 'Cross-origin requests are not allowed.';
  }

  if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(method)
      && !String(headers['content-type'] || '').includes('application/json')) {
    return 'Requests that change something must use Content-Type: application/json.';
  }
  return null;
}

// Read + JSON-parse a request body from a Node IncomingMessage, capped at a max
// size. Returns {} on empty/invalid JSON (handlers validate their own inputs).
function readJsonBody(req, maxBytes = 1_000_000) {
  return new Promise((resolve, reject) => {
    let data = '';
    let done = false;
    req.on('data', chunk => {
      data += chunk;
      if (data.length > maxBytes && !done) {
        done = true;
        const err = new Error('Payload too large.');
        err.status = 413;
        err.expose = true;
        reject(err);
        req.destroy();
      }
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); }
    });
    req.on('error', err => { if (!done) { done = true; reject(err); } });
  });
}

// Resolve the real client IP. X-Forwarded-For is CLIENT-CONTROLLED and is only
// honored when trustProxy is set (i.e. we are genuinely behind a proxy that
// sets it). Otherwise we use the socket peer address, so a client cannot spoof
// XFF to mint fresh rate-limit buckets.
//
// HOP SELECTION: trusted proxies APPEND to XFF, so the last `trustedProxyHops`
// entries are proxy-written and the real client is xff[len - trustedProxyHops].
// `trustedProxyHops` MUST exactly equal the number of proxies that append XFF
// between the client and this backend.
//
// FAIL CLOSED: if the XFF is shorter than the trusted hop count (a request that
// skipped the proxy, or a misconfiguration), we do NOT fall back to the
// client-controlled LEFTMOST entry (that re-opens the XFF spoofing bypass) —
// we fall back to the socket peer address instead.
function resolveClientIp(headers, socketRemoteAddress, trustProxy = false, trustedProxyHops = 1) {
  const socket = socketRemoteAddress || '';
  if (!trustProxy) return socket;
  const xff = headers['x-forwarded-for'];
  if (!xff) return socket;
  const list = String(xff).split(',').map(s => s.trim()).filter(Boolean);
  const hops = Math.max(1, Number(trustedProxyHops) || 1);
  const idx = list.length - hops;
  if (idx < 0) return socket;        // fail closed — never list[0]
  return list[idx] || socket;
}

module.exports = { requestBlockReason, readJsonBody, resolveClientIp };
