'use strict';
// Password hashing with scrypt (Node built-in — memory-hard, zero native dep,
// serverless-safe). Encoded string is self-describing so parameters can be
// upgraded over time while old hashes still verify:
//
//   scrypt$<N>$<r>$<p>$<salt_b64>$<hash_b64>

const crypto = require('crypto');

const DEFAULTS = { N: 1 << 15, r: 8, p: 1, keylen: 32 };

// scrypt needs ~128*N*r bytes; give generous headroom above Node's 32MB default
// so strong params (N=2^15, r=8 ≈ 33.5MB) don't hit the maxmem ceiling.
function maxmemFor(N, r) {
  return Math.max(64 * 1024 * 1024, 256 * N * r);
}

function hashPassword(password, params = DEFAULTS) {
  const { N, r, p, keylen } = { ...DEFAULTS, ...params };
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(
    Buffer.from(String(password), 'utf8'), salt, keylen,
    { N, r, p, maxmem: maxmemFor(N, r) },
  );
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(password, encoded) {
  try {
    const parts = String(encoded).split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const N = Number(parts[1]);
    const r = Number(parts[2]);
    const p = Number(parts[3]);
    const salt = Buffer.from(parts[4], 'base64');
    const expected = Buffer.from(parts[5], 'base64');
    if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p) || expected.length === 0) {
      return false;
    }
    const actual = crypto.scryptSync(
      Buffer.from(String(password), 'utf8'), salt, expected.length,
      { N, r, p, maxmem: maxmemFor(N, r) },
    );
    // Lengths are equal by construction (keylen = expected.length), but guard
    // anyway — timingSafeEqual throws on length mismatch.
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword, DEFAULTS };
