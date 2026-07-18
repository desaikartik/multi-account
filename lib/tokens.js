'use strict';
// Token primitives.
//
// ACCESS TOKEN: a compact JWS (JWT) signed with Ed25519 using Node's built-in
// crypto (EdDSA). We deliberately do NOT depend on `jose` so the entire suite
// runs offline with nothing installed, and the whole crypto surface is Node
// built-ins (consistent with scrypt/AES-GCM/HMAC elsewhere).
//
//   Carries IDENTITY ONLY: sub (userId), role (advisory), did (deviceId).
//   NEVER carries entitlement flags — those are read live from `users` on every
//   gated call (see entitlements.js) so admin revocation is instant.
//
// REFRESH TOKEN: opaque 256-bit random string. Only its SHA-256 hash is stored
// (the token itself is high-entropy, so a fast hash is appropriate — unlike a
// password). Rotation + reuse-detection live in auth.js.

const crypto = require('crypto');
const { httpError } = require('./errors');

const ISS = 'managed-switcher';

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function signAccessToken(ctx, { userId, role, deviceId, scope }) {
  const nowSec = Math.floor(ctx.clock.nowMs() / 1000);
  const header = { alg: 'EdDSA', typ: 'JWT' };
  const payload = {
    iss: ISS,
    sub: userId,
    role,
    did: deviceId,
    iat: nowSec,
    exp: Math.floor((ctx.clock.nowMs() + ctx.config.accessTokenTtlMs) / 1000),
    jti: crypto.randomUUID(),
  };
  // Optional privilege-reduction claim. Only ever set explicitly to 'view' by
  // callers that mint a view-only (web console) token; the key is omitted
  // entirely otherwise so existing/legacy tokens are indistinguishable from
  // full-privilege tokens (absence of the claim == full privilege).
  if (scope) payload.scope = scope;
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = crypto.sign(null, Buffer.from(signingInput), ctx.config.jwtPrivateKey);
  return `${signingInput}.${sig.toString('base64url')}`;
}

function verifyAccessToken(ctx, token) {
  const bad = () => httpError(401, 'Invalid token.');
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw bad();
  const [h, p, s] = parts;

  let header;
  try { header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8')); } catch { throw bad(); }
  // Reject alg confusion / "none": we ONLY accept EdDSA.
  if (!header || header.alg !== 'EdDSA' || header.typ !== 'JWT') throw bad();

  const signingInput = `${h}.${p}`;
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(signingInput), ctx.config.jwtPublicKey, Buffer.from(s, 'base64url'));
  } catch { ok = false; }
  if (!ok) throw bad();

  let payload;
  try { payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch { throw bad(); }
  if (payload.iss !== ISS) throw bad();
  const nowSec = Math.floor(ctx.clock.nowMs() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= nowSec) throw httpError(401, 'Token expired.');
  return payload;
}

function generateRefreshToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(String(token), 'utf8').digest('base64');
}

module.exports = { signAccessToken, verifyAccessToken, generateRefreshToken, hashRefreshToken, ISS };
