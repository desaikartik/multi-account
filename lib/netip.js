'use strict';
// IP address utilities for Phase 2: canonicalization, CIDR matching, and
// record-bound field encryption / blind index for IPs.
//
// WHY canonicalization matters: the blind index (HMAC) and CIDR matching both
// operate on exact bytes, so two textual forms of the SAME address must be
// folded to one canonical string FIRST, or equality search silently breaks and
// a block rule can be bypassed. Sources of textual variance we normalize:
//   - IPv4-mapped IPv6:  ::ffff:1.2.3.4        → 1.2.3.4   (dual-stack proxies)
//   - mixed case / zero-compression in IPv6:   2001:DB8::1 → 2001:db8::1
//   - bracket + port forms:  [2001:db8::1]:443, 1.2.3.4:5678 → strip port
//
// ipEnc uses a RECORD-BOUND AAD (ip:<recordCtx>) so a ciphertext cannot be
// relocated to a different record undetected; ipIdx stays globally keyed so
// equality search across records still works.

const net = require('net');

// --- canonicalization ------------------------------------------------------

function stripBracketsAndPort(s) {
  if (s[0] === '[') {
    const end = s.indexOf(']');
    return end === -1 ? s.slice(1) : s.slice(1, end);
  }
  // "1.2.3.4:5678" — a lone colon on a dotted-quad is an IPv4:port form.
  if ((s.split(':').length - 1) === 1 && s.includes('.')) return s.split(':')[0];
  return s;
}

// Fold an IPv4-mapped IPv6 (::ffff:hhhh:hhhh) to dotted-quad. Accepts both the
// textual dotted form and the two-hex-group form (after v6 normalization).
function mappedV4(s) {
  const dotted = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (dotted) return dotted[1];
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(s);
  if (hex) {
    const n = ((parseInt(hex[1], 16) & 0xffff) * 65536) + (parseInt(hex[2], 16) & 0xffff);
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  return null;
}

// RFC-5952 compressed, lowercase IPv6 via the WHATWG URL parser (built-in).
function normalizeV6(s) {
  try {
    const host = new URL('http://[' + s + ']/').hostname; // e.g. "[2001:db8::1]"
    return host.replace(/^\[|\]$/g, '');
  } catch {
    return s;
  }
}

// Canonicalize any IP string to a single stable form. Returns '' for empty
// input and returns the (lowercased, de-ported) string unchanged if it is not
// a recognizable IP, so callers never crash on junk.
function canonicalizeIp(ip) {
  let s = String(ip == null ? '' : ip).trim();
  if (!s) return '';
  s = stripBracketsAndPort(s).toLowerCase();
  const early = mappedV4(s);
  if (early) return early;
  if (net.isIPv4(s)) return s;
  if (net.isIPv6(s)) {
    const norm = normalizeV6(s);
    return mappedV4(norm) || norm;
  }
  return s;
}

// --- integer conversion ----------------------------------------------------

function v4ToBigInt(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    const b = Number(p);
    if (!Number.isInteger(b) || b < 0 || b > 255) return null;
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

function v6Groups(s) {
  // Convert an embedded IPv4 tail (::a.b.c.d) into two hex groups first.
  if (s.includes('.')) {
    const lastColon = s.lastIndexOf(':');
    const v4 = s.slice(lastColon + 1).split('.').map(Number);
    if (v4.length !== 4 || v4.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return null;
    const g1 = ((v4[0] << 8) | v4[1]).toString(16);
    const g2 = ((v4[2] << 8) | v4[3]).toString(16);
    s = s.slice(0, lastColon + 1) + g1 + ':' + g2;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  if (halves.length === 1) {
    return left.length === 8 ? left : null;
  }
  const right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0) return null;
  return [...left, ...Array(missing).fill('0'), ...right];
}

function v6ToBigInt(s) {
  const groups = v6Groups(s);
  if (!groups) return null;
  let n = 0n;
  for (const g of groups) {
    const v = parseInt(g || '0', 16);
    if (Number.isNaN(v) || v < 0 || v > 0xffff) return null;
    n = (n << 16n) | BigInt(v);
  }
  return n;
}

function ipToBigInt(canon) {
  if (net.isIPv4(canon)) return { n: v4ToBigInt(canon), bits: 32 };
  if (net.isIPv6(canon)) return { n: v6ToBigInt(canon), bits: 128 };
  return null;
}

// --- CIDR ------------------------------------------------------------------

// Parse "addr/prefix" (or a bare "addr" = host route). Returns { n, bits,
// prefix } or null if malformed. Canonicalizes the address (so an IPv4-mapped
// rule matches a dotted-quad address and vice versa).
function parseCidr(cidr) {
  const raw = String(cidr == null ? '' : cidr).trim();
  if (!raw) return null;
  const slash = raw.indexOf('/');
  const addrPart = slash === -1 ? raw : raw.slice(0, slash);
  const canon = canonicalizeIp(addrPart);
  const info = ipToBigInt(canon);
  if (!info || info.n === null) return null;
  let prefix;
  if (slash === -1) {
    prefix = info.bits; // host route
  } else {
    prefix = Number(raw.slice(slash + 1));
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > info.bits) return null;
  }
  return { n: info.n, bits: info.bits, prefix };
}

function isValidCidr(cidr) {
  return parseCidr(cidr) !== null;
}

function maskOf(bits, prefix) {
  if (prefix === 0) return 0n;
  const full = (1n << BigInt(bits)) - 1n;
  return (full << BigInt(bits - prefix)) & full;
}

// True iff `ip` falls within `cidr`. Cross-family (v4 addr vs v6 rule) → false,
// never throws (so a malformed rule can never 500 the request pipeline).
function ipInCidr(ip, cidr) {
  const rule = parseCidr(cidr);
  if (!rule) return false;
  const canon = canonicalizeIp(ip);
  const info = ipToBigInt(canon);
  if (!info || info.n === null) return false;
  if (info.bits !== rule.bits) return false; // different family
  const mask = maskOf(rule.bits, rule.prefix);
  return (info.n & mask) === (rule.n & mask);
}

// --- record-bound IP field crypto ------------------------------------------

// Returns { ipEnc, ipIdx } for a raw IP, or { ipEnc:null, ipIdx:null } for an
// empty/missing IP (never encrypts the empty string — that would create a
// spurious equality-matchable index across all IP-less records).
function encryptIp(ctx, ip, recordCtx) {
  const canon = canonicalizeIp(ip);
  if (!canon) return { ipEnc: null, ipIdx: null };
  return { ipEnc: ctx.crypto.encrypt(canon, aadFor(recordCtx)), ipIdx: ctx.crypto.blindIndex(canon) };
}

function decryptIp(ctx, ipEnc, recordCtx) {
  if (ipEnc == null) return null;
  return ctx.crypto.decrypt(ipEnc, aadFor(recordCtx));
}

function ipIdxOf(ctx, ip) {
  const canon = canonicalizeIp(ip);
  return canon ? ctx.crypto.blindIndex(canon) : null;
}

function aadFor(recordCtx) {
  return 'ip:' + (recordCtx == null ? '' : String(recordCtx));
}

module.exports = {
  canonicalizeIp, ipInCidr, parseCidr, isValidCidr,
  encryptIp, decryptIp, ipIdxOf,
};
