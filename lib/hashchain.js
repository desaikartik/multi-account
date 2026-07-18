'use strict';
// Tamper-evident append-only hash chain (shared by permission_changes and
// audit_events).
//
//   entryHash = HMAC-SHA256(hmacKey, `${seq}|${prevHash}|${canonicalJSON(core)}`)
//
// "core" = every field of the stored doc EXCEPT the chain metadata
// (_id, seq, prevHash, entryHash). canonicalJSON sorts keys recursively so the
// hash is representation-independent. Dates are hashed as their ISO-8601 string.
//
// Concurrency: appendChained reads the head, computes seq = head.seq + 1, and
// inserts. The append-only collection has a unique {seq} constraint; if a
// concurrent writer took that seq first, the insert fails with DUPLICATE_SEQ and
// we retry against the new head. This is the same pattern used against Mongo's
// unique index — no lost or duplicated links under contention.

const crypto = require('crypto');

const GENESIS = 'GENESIS';
const RESERVED = new Set(['_id', 'seq', 'prevHash', 'entryHash']);
const DEFAULT_MAX_RETRIES = 100;

// Deterministic, key-order-independent JSON. Throws on non-finite numbers and
// unsupported types so a bad value can never produce an unverifiable entry.
function canonicalJson(value) {
  if (value === null || value === undefined) return 'null';
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (t === 'boolean' || t === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
  }
  throw new Error('canonicalJson: unsupported type ' + t);
}

function coreOf(doc) {
  const out = {};
  for (const k of Object.keys(doc)) if (!RESERVED.has(k)) out[k] = doc[k];
  return out;
}

// `domain` is a per-ledger tag bound into the MAC material. Two chains that
// share the same HMAC key (audit_events + permission_changes) get DIFFERENT
// hashes for identical (seq, prevHash, core), so rows cannot be transplanted
// from one ledger to the other even with DB write access.
function computeEntryHash(hmacKey, seq, prevHash, core, domain = '') {
  const material = `${domain}|${seq}|${prevHash}|${canonicalJson(core)}`;
  return crypto.createHmac('sha256', hmacKey).update(material, 'utf8').digest('base64');
}

async function appendChained(ctx, collection, hmacKey, core, opts = {}) {
  // Guard: core must not collide with chain metadata keys.
  for (const k of Object.keys(core)) {
    if (RESERVED.has(k)) throw new Error(`chain core may not contain reserved key "${k}"`);
  }
  const domain = opts.domain || '';
  const maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES;
  for (let attempt = 0; ; attempt++) {
    const head = await collection.getHead();
    const seq = head ? head.seq + 1 : 1;
    const prevHash = head ? head.entryHash : GENESIS;
    const entryHash = computeEntryHash(hmacKey, seq, prevHash, core, domain);
    try {
      return await collection.insert({ seq, prevHash, entryHash, ...core });
    } catch (err) {
      if (err && err.code === 'DUPLICATE_SEQ' && attempt < maxRetries) continue;
      throw err;
    }
  }
}

// Walk entries in seq order, recomputing each hash and checking the prev link.
// Returns { ok, ... }. On failure includes { reason, seq }.
function verifyChain(entries, hmacKey, opts = {}) {
  const domain = opts.domain || '';
  const sorted = [...entries].sort((a, b) => a.seq - b.seq);
  let expectedPrev = opts.startPrevHash || GENESIS;
  let expectedSeq = opts.startSeq || 1;
  for (const e of sorted) {
    if (e.seq !== expectedSeq) return { ok: false, reason: 'seq_gap', seq: e.seq, expectedSeq };
    if (e.prevHash !== expectedPrev) return { ok: false, reason: 'prev_hash_mismatch', seq: e.seq };
    const recomputed = computeEntryHash(hmacKey, e.seq, e.prevHash, coreOf(e), domain);
    if (recomputed !== e.entryHash) return { ok: false, reason: 'entry_hash_mismatch', seq: e.seq };
    expectedPrev = e.entryHash;
    expectedSeq = e.seq + 1;
  }
  return { ok: true, count: sorted.length, headHash: expectedPrev, headSeq: expectedSeq - 1 };
}

module.exports = { canonicalJson, coreOf, computeEntryHash, appendChained, verifyChain, GENESIS };
