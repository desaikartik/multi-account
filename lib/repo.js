'use strict';
// Repository interface + in-memory implementation.
//
// Queries use a small MongoDB-style FILTER OBJECT (not JS predicates) so the
// exact same call sites work against both the in-memory repo (tests) and the
// mongodb driver (mongoRepo.js, production) — no full-collection scans.
//
//   find({ emailIdx })                              equality
//   find({ userId, purpose, consumedAt: null })     null matches null/missing
//   count({ createdAt: { $gte: windowStart } })     operators: $gt/$gte/$lt/$lte/$ne/$in
//
// Collection shapes:
//   Mutable (users, otps, sessions, devices, auditAnchors):
//     insert, findById, findOne, find, updateById, deleteById, count
//   Append-only (auditEvents, permissionChanges):
//     insert (unique seq + unique idempotencyKey), getHead, findOne, find,
//     count, findByIdempotencyKey            <-- NO update/delete (tamper-evidence)

const crypto = require('crypto');

function deepClone(v) {
  if (v === null || typeof v !== 'object') return v;
  if (v instanceof Date) return new Date(v.getTime());
  if (Buffer.isBuffer(v)) return Buffer.from(v);
  if (Array.isArray(v)) return v.map(deepClone);
  const out = {};
  for (const k of Object.keys(v)) out[k] = deepClone(v[k]);
  return out;
}

function genId() { return crypto.randomUUID(); }

// Apply a Mongo-style update spec ({ $set, $inc }) to a doc in place.
function applyUpdate(doc, spec) {
  if (spec.$set) for (const [k, v] of Object.entries(spec.$set)) doc[k] = v;
  if (spec.$inc) for (const [k, v] of Object.entries(spec.$inc)) doc[k] = (doc[k] || 0) + v;
  return doc;
}

// --- tiny filter matcher (shared query semantics with Mongo) ---------------

function isPlainObject(v) {
  return v !== null && typeof v === 'object'
    && !(v instanceof Date) && !Buffer.isBuffer(v) && !Array.isArray(v);
}
function comparable(v) { return v instanceof Date ? v.getTime() : v; }
function valueEquals(a, b) {
  const x = a === undefined ? null : a;
  const y = b === undefined ? null : b;
  if (x instanceof Date || y instanceof Date) return comparable(x) === comparable(y);
  return x === y;
}
function matchField(docVal, cond) {
  if (isPlainObject(cond)) {
    const keys = Object.keys(cond);
    if (keys.length && keys.every(k => k.startsWith('$'))) {
      for (const op of keys) {
        const c = cond[op];
        const dv = comparable(docVal);
        const cv = comparable(c);
        switch (op) {
          case '$gte': if (!(dv >= cv)) return false; break;
          case '$gt': if (!(dv > cv)) return false; break;
          case '$lte': if (!(dv <= cv)) return false; break;
          case '$lt': if (!(dv < cv)) return false; break;
          case '$ne': if (valueEquals(docVal, c)) return false; break;
          case '$in': if (!Array.isArray(c) || !c.some(x => valueEquals(docVal, x))) return false; break;
          default: throw new Error('unsupported query operator ' + op);
        }
      }
      return true;
    }
  }
  return valueEquals(docVal, cond);
}
function matchDoc(doc, filter) {
  if (typeof filter === 'function') throw new Error('repository queries use filter objects, not predicates');
  for (const key of Object.keys(filter || {})) {
    if (!matchField(doc[key], filter[key])) return false;
  }
  return true;
}

// --- collections -----------------------------------------------------------

// uniqueSpecs: [{ field, code }] — enforces a unique index on `field`, throwing
// an error with the given `code` on collision (mirrors a Mongo unique index).
function mutableCollection(uniqueSpecs = []) {
  const byId = new Map();
  const indexes = uniqueSpecs.map(s => ({ ...s, values: new Map() }));
  return {
    async insert(doc) {
      for (const ix of indexes) {
        const v = doc[ix.field];
        if (v != null && ix.values.has(v)) {
          const err = new Error(`duplicate ${ix.field}`);
          err.code = ix.code;
          throw err;
        }
      }
      const _id = doc._id || genId();
      const stored = deepClone({ ...doc, _id });
      byId.set(_id, stored);
      for (const ix of indexes) if (stored[ix.field] != null) ix.values.set(stored[ix.field], _id);
      return deepClone(stored);
    },
    async findById(id) {
      const d = byId.get(id);
      return d ? deepClone(d) : null;
    },
    async findOne(filter = {}) {
      for (const d of byId.values()) if (matchDoc(d, filter)) return deepClone(d);
      return null;
    },
    async find(filter = {}) {
      const out = [];
      for (const d of byId.values()) if (matchDoc(d, filter)) out.push(deepClone(d));
      return out;
    },
    async updateById(id, patch) {
      const d = byId.get(id);
      if (!d) return null;
      const updated = { ...d, ...deepClone(patch), _id: id };
      byId.set(id, updated);
      return deepClone(updated);
    },
    // Atomic find-one-matching-filter-and-update. Returns the updated doc, or
    // null if nothing matched. Atomic in-memory (no await inside the critical
    // section); Mongo maps this to findOneAndUpdate — so a guarded update like
    // { attempts: { $lt: max } } enforces a cap with no TOCTOU window.
    async updateOne(filter, spec) {
      for (const d of byId.values()) {
        if (matchDoc(d, filter)) {
          applyUpdate(d, { $set: deepClone(spec.$set), $inc: spec.$inc });
          return deepClone(d);
        }
      }
      return null;
    },
    async deleteById(id) {
      return byId.delete(id);
    },
    async count(filter = {}) {
      let n = 0;
      for (const d of byId.values()) if (matchDoc(d, filter)) n++;
      return n;
    },
    _all() { return [...byId.values()].map(deepClone); },
  };
}

function appendOnlyCollection() {
  const bySeq = new Map();
  const byIdem = new Map(); // idempotencyKey → seq (mirrors a Mongo unique index)
  let headSeq = 0;
  return {
    async insert(doc) {
      if (typeof doc.seq !== 'number' || !Number.isInteger(doc.seq)) {
        throw new Error('append-only insert requires an integer seq');
      }
      if (bySeq.has(doc.seq)) {
        const err = new Error(`duplicate key: seq ${doc.seq} already exists`);
        err.code = 'DUPLICATE_SEQ';
        throw err;
      }
      if (doc.idempotencyKey != null && byIdem.has(doc.idempotencyKey)) {
        const err = new Error('duplicate idempotency key');
        err.code = 'DUPLICATE_IDEMPOTENCY';
        throw err;
      }
      const _id = doc._id || genId();
      const stored = deepClone({ ...doc, _id });
      bySeq.set(doc.seq, stored);
      if (doc.idempotencyKey != null) byIdem.set(doc.idempotencyKey, doc.seq);
      if (doc.seq > headSeq) headSeq = doc.seq;
      return deepClone(stored);
    },
    async getHead() {
      if (headSeq === 0) return null;
      return deepClone(bySeq.get(headSeq));
    },
    async findByIdempotencyKey(key) {
      if (key == null || !byIdem.has(key)) return null;
      return deepClone(bySeq.get(byIdem.get(key)));
    },
    async findOne(filter = {}) {
      for (const d of bySeq.values()) if (matchDoc(d, filter)) return deepClone(d);
      return null;
    },
    async find(filter = {}) {
      const out = [];
      for (const d of bySeq.values()) if (matchDoc(d, filter)) out.push(deepClone(d));
      out.sort((a, b) => a.seq - b.seq);
      return out;
    },
    async count(filter = {}) {
      let n = 0;
      for (const d of bySeq.values()) if (matchDoc(d, filter)) n++;
      return n;
    },
    // Anchor-aligned retention prune: delete entries with seq <= boundarySeq.
    // NEVER deletes the head (seq === headSeq) and NEVER lowers headSeq, so the
    // next insert still gets head.seq+1 (no seq reuse / chain corruption). In
    // production this is called under a SEPARATE privileged connection — the
    // app's own Mongo role stays insert+find-only for tamper-evidence.
    async deleteBelowSeq(boundarySeq) {
      let n = 0;
      for (const [seq, doc] of [...bySeq.entries()]) {
        if (seq <= boundarySeq && seq !== headSeq) {
          bySeq.delete(seq);
          if (doc.idempotencyKey != null) byIdem.delete(doc.idempotencyKey);
          n++;
        }
      }
      return n;
    },
    _all() { return [...bySeq.values()].map(deepClone).sort((a, b) => a.seq - b.seq); },
  };
}

function createMemoryRepo() {
  const collections = {
    users: mutableCollection([{ field: 'emailIdx', code: 'DUPLICATE_EMAIL' }]),
    otps: mutableCollection(),
    sessions: mutableCollection(),
    devices: mutableCollection(),
    auditAnchors: mutableCollection(),
    permAnchors: mutableCollection(),           // own anchors for permission_changes (gap #3)
    ipRules: mutableCollection(),               // allow/block CIDR rules (global + per-user)
    watermarks: mutableCollection(),            // _id = watermarkId; export origin
    watermarkImports: mutableCollection([{ field: 'dedupeKey', code: 'DUPLICATE_WMI' }]), // one row per (watermark,user,device,file)
    commands: mutableCollection(),              // _id = commandId; remote-command queue (separate collection: atomic CAS)
    loginAttempts: mutableCollection(),         // per-IP failed-login counter (serverless-safe dedup for repeated-fail anomaly)
    usageSnapshots: mutableCollection(),        // one doc per (user,account), updated in place (lib/usagestore.js) — NOT the audit ledger
    auditEvents: appendOnlyCollection(),
    permissionChanges: appendOnlyCollection(),
  };
  return {
    ...collections,
    // Rough byte estimate for the storage-% report. Deterministic given the
    // data; overridable in tests to exercise the [0,100] clamp. Mongo uses
    // db.stats().dataSize (see mongoRepo.js) — same {estimatedBytes} shape.
    async stats() {
      let bytes = 0;
      for (const c of Object.values(collections)) {
        for (const d of c._all()) bytes += JSON.stringify(d).length;
      }
      return { estimatedBytes: bytes };
    },
    async close() { /* no-op for in-memory */ },
  };
}

module.exports = { createMemoryRepo, deepClone, matchDoc };
