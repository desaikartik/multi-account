'use strict';
// Production repository backed by the mongodb driver. Implements the SAME
// interface as createMemoryRepo() (repo.js), and the SAME filter-object query
// language — so filters pass through to Mongo directly (equality, $gte/$lte/
// $gt/$lt/$ne/$in; null matches null-or-missing, exactly like Mongo).
//
// NOT exercised by `node --test` (that needs no DB). This is the real adapter,
// integration-verified against Atlas during deploy (Phase 6). mongodb is
// lazy-required so the test suite never needs it installed.
//
// Connection reuse: a module-level cached client (serverless-safe — a warm
// Vercel/Render instance reuses the pool across invocations).
//
// ROLE SPLIT (Phase 6 Task 3) — exactly which Mongo ops each role needs:
//   APP ROLE (config.mongoUri, the `cached` singleton below):
//     - insert + find on every collection (mutableCollection + appendOnlyCollection)
//     - deleteOne on `ip_rules` ONLY (mutableCollection.deleteById — access.js
//       removeIpRule; the sole mutable-collection delete the app performs)
//     - updateById/updateOne on mutable collections
//     - createIndex at startup (ensureIndexes(), first connect)
//     - db.stats() (storage report, createMongoRepo().stats())
//     - The app role must NEVER be granted delete on audit_events or
//       permission_changes — that is the entire point of this split.
//   PRUNE ROLE (config.mongoPruneUri, a SEPARATE un-cached connection built by
//     passing { uriOverride } below, wired as ctx.pruneRepo in context.js):
//     - deleteMany, and ONLY on audit_events + permission_changes, and ONLY
//       via deleteBelowSeq() (appendOnlyCollection, below). No insert, no
//       find, no createIndex, no other collection — retention.pruneAnchorAligned
//       (lib/retention.js) only ever hands this handle its own deleteEvents
//       param; every read it needs (getHead/findOne/anchors.find) goes through
//       the app-role `events`/`anchors` handles instead.

const crypto = require('crypto');

let cached = null; // { client, db } — APP ROLE singleton ONLY. A uriOverride
                    // (prune-role) connection is never stored here and never
                    // read from here — see getDb() below.

// getDb(config, { uriOverride }): uriOverride, when present, opens a brand
// new, un-cached MongoClient against that URI (the prune role) and returns
// early — it never touches the module-level `cached` app singleton in either
// direction (doesn't read it, doesn't overwrite it, doesn't run
// ensureIndexes — the prune role's Atlas grant must not include createIndex).
// Without uriOverride, behavior is byte-identical to before this task: warm
// reuse via `cached`, connect + ensureIndexes on first call.
async function getDb(config, { uriOverride } = {}) {
  if (uriOverride) {
    const { MongoClient } = require('mongodb'); // lazy
    const client = new MongoClient(uriOverride, {
      ignoreUndefined: true,
      retryWrites: true,
    });
    await client.connect();
    const db = client.db(config.mongoDb);
    return { db, client };
  }
  if (cached) return { db: cached.db, client: cached.client };
  const { MongoClient } = require('mongodb'); // lazy
  const client = new MongoClient(config.mongoUri, {
    // Least-privilege SCRAM user + TLS are configured on the Atlas side.
    ignoreUndefined: true,
    retryWrites: true,
  });
  await client.connect();
  const db = client.db(config.mongoDb);
  cached = { client, db };
  await ensureIndexes(db); // APP ROLE: createIndex
  return { db, client };
}

async function ensureIndexes(db) {
  await db.collection('users').createIndex({ emailIdx: 1 }, { unique: true });
  await db.collection('users').createIndex({ role: 1 });

  await db.collection('otps').createIndex({ userId: 1, purpose: 1 });
  await db.collection('otps').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

  await db.collection('sessions').createIndex({ tokenHash: 1 }, { unique: true });
  await db.collection('sessions').createIndex({ familyId: 1 });
  await db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

  await db.collection('devices').createIndex({ userId: 1 });

  const audit = db.collection('audit_events');
  await audit.createIndex({ seq: 1 }, { unique: true });
  await audit.createIndex(
    { idempotencyKey: 1 },
    { unique: true, partialFilterExpression: { idempotencyKey: { $exists: true } } },
  );
  await audit.createIndex({ userId: 1, serverTs: -1 });
  await audit.createIndex({ eventType: 1, serverTs: -1 });
  await audit.createIndex({ severity: 1, serverTs: -1 });
  await audit.createIndex({ watermarkId: 1 });
  // NOTE: deliberately NO raw serverTs TTL. A time-based TTL prunes the chain at
  // boundaries unrelated to anchors, which breaks seq-based verification (a
  // pruned prefix leaves the tail's prevHash un-anchored). 7-day retention
  // (Addendum B) is a Phase-2 ANCHOR-ALIGNED prune job: anchor the head, then
  // delete only events strictly below the newest anchor's seqHigh, so the
  // retained tail always starts exactly at an anchor checkpoint.

  await db.collection('audit_anchors').createIndex({ seqHigh: 1 }, { unique: true });

  const perm = db.collection('permission_changes');
  await perm.createIndex({ seq: 1 }, { unique: true });
  await perm.createIndex({ targetUserId: 1 });
  await perm.createIndex({ adminId: 1 });
  // Own anchors for permission_changes (gap #3): tail-truncation detection.
  await db.collection('perm_anchors').createIndex({ seqHigh: 1 }, { unique: true });

  // Phase 2 control-plane collections.
  const ipRules = db.collection('ip_rules');
  await ipRules.createIndex({ scope: 1, type: 1 });
  await ipRules.createIndex({ userId: 1 });

  await db.collection('watermarks').createIndex({ fileSha256: 1 });
  const wmi = db.collection('watermark_imports');
  await wmi.createIndex({ watermarkId: 1 });                       // trace joins
  await wmi.createIndex({ dedupeKey: 1 }, { unique: true });       // one row per (watermark,user,device,file)

  const commands = db.collection('commands');
  await commands.createIndex({ deviceId: 1, status: 1 });
  await commands.createIndex({ userId: 1 });

  await db.collection('login_attempts').createIndex({ ipIdx: 1 }, { unique: true });

  // Usage tracking (lib/usagestore.js) — one doc per (user,account), updated
  // in place; NOT the audit ledger. { userId: 1 } backs myUsage's self-scoped
  // read; { updatedAt: 1 } backs reporting.usageOverview's window filter AND
  // doubles as a TTL (14 d) so a departed user/account self-cleans — safe
  // here (an ordinary mutable collection), unlike the audit_events ledger's
  // deliberate no-TTL policy noted above.
  const usage = db.collection('usage_snapshots');
  await usage.createIndex({ userId: 1 });
  await usage.createIndex({ updatedAt: 1 }, { expireAfterSeconds: 1209600 });
}

function genId() { return crypto.randomUUID(); }

// Map a Mongo duplicate-key error to our sentinel codes so the service layer's
// retry / idempotency handling works identically to the in-memory repo.
function mapDupKey(err) {
  if (err && err.code === 11000) {
    const key = err.keyPattern || (err.keyValue ? Object.fromEntries(Object.keys(err.keyValue).map(k => [k, 1])) : {});
    if (key.idempotencyKey) { const e = new Error('duplicate idempotency key'); e.code = 'DUPLICATE_IDEMPOTENCY'; return e; }
    if (key.seq) { const e = new Error('duplicate seq'); e.code = 'DUPLICATE_SEQ'; return e; }
    if (key.emailIdx) { const e = new Error('duplicate email'); e.code = 'DUPLICATE_EMAIL'; return e; }
    if (key.dedupeKey) { const e = new Error('duplicate watermark import'); e.code = 'DUPLICATE_WMI'; return e; }
  }
  return err;
}

function mutableCollection(coll) {
  return {
    async insert(doc) {
      const _id = doc._id || genId();
      const toStore = { ...doc, _id };
      try { await coll.insertOne(toStore); } catch (err) { throw mapDupKey(err); }
      return toStore;
    },
    findById(id) { return coll.findOne({ _id: id }); },
    findOne(filter = {}) { return coll.findOne(filter); },
    find(filter = {}) { return coll.find(filter).toArray(); },
    async updateById(id, patch) {
      const res = await coll.findOneAndUpdate(
        { _id: id }, { $set: patch }, { returnDocument: 'after' },
      );
      return res && (res.value !== undefined ? res.value : res);
    },
    async updateOne(filter, spec) {
      const update = {};
      if (spec.$set) update.$set = spec.$set;
      if (spec.$inc) update.$inc = spec.$inc;
      const res = await coll.findOneAndUpdate(filter, update, { returnDocument: 'after' });
      return res && (res.value !== undefined ? res.value : res);
    },
    async deleteById(id) {
      const res = await coll.deleteOne({ _id: id });
      return res.deletedCount > 0;
    },
    count(filter = {}) { return coll.countDocuments(filter); },
  };
}

function appendOnlyCollection(coll) {
  return {
    async insert(doc) {
      const _id = doc._id || genId();
      const toStore = { ...doc, _id };
      try { await coll.insertOne(toStore); } catch (err) { throw mapDupKey(err); }
      return toStore;
    },
    async getHead() {
      return coll.find({}).sort({ seq: -1 }).limit(1).next();
    },
    findByIdempotencyKey(key) {
      if (key == null) return Promise.resolve(null);
      return coll.findOne({ idempotencyKey: key });
    },
    findOne(filter = {}) { return coll.findOne(filter); },
    find(filter = {}) { return coll.find(filter).sort({ seq: 1 }).toArray(); },
    count(filter = {}) { return coll.countDocuments(filter); },
    // Anchor-aligned retention prune (Phase 2). Deletes chained events at or
    // below a boundary seq. This is the ONLY delete on an append-only ledger and
    // it MUST run under a SEPARATE privileged Mongo connection/role — the app's
    // own role stays insert+find only (spec §6.3) so the app can never delete
    // ledger rows. The caller (retention.js) only ever passes a boundary strictly
    // below the current head, so the head is never removed.
    async deleteBelowSeq(boundarySeq) {
      const res = await coll.deleteMany({ seq: { $lte: boundarySeq } });
      return res.deletedCount || 0;
    },
    // NO updateById — append-only rows are immutable (tamper-evidence).
  };
}

// createMongoRepo(config, { uriOverride }): the normal (app-role) call is
// createMongoRepo(config) — unchanged. Phase 6 Task 3 adds an optional
// second arg: createMongoRepo(config, { uriOverride: config.mongoPruneUri })
// opens a SEPARATE, un-cached connection under that URI (see getDb() above)
// and returns the SAME repo shape so callers (retention.js via ctx.pruneRepo)
// can use whichever collection handles they need — in practice only
// .auditEvents/.permissionChanges .deleteBelowSeq() is ever called on it.
async function createMongoRepo(config, { uriOverride } = {}) {
  const { db, client } = await getDb(config, { uriOverride });
  return {
    users: mutableCollection(db.collection('users')),
    otps: mutableCollection(db.collection('otps')),
    sessions: mutableCollection(db.collection('sessions')),
    devices: mutableCollection(db.collection('devices')),
    auditAnchors: mutableCollection(db.collection('audit_anchors')),
    permAnchors: mutableCollection(db.collection('perm_anchors')),
    ipRules: mutableCollection(db.collection('ip_rules')), // APP ROLE: deleteOne (access.js removeIpRule) — the only mutable-collection delete
    watermarks: mutableCollection(db.collection('watermarks')),
    watermarkImports: mutableCollection(db.collection('watermark_imports')),
    commands: mutableCollection(db.collection('commands')),
    loginAttempts: mutableCollection(db.collection('login_attempts')),
    usageSnapshots: mutableCollection(db.collection('usage_snapshots')), // one doc per (user,account), updated in place — NOT the audit ledger
    auditEvents: appendOnlyCollection(db.collection('audit_events')), // .deleteBelowSeq() = PRUNE ROLE ONLY in production
    permissionChanges: appendOnlyCollection(db.collection('permission_changes')), // .deleteBelowSeq() = PRUNE ROLE ONLY in production
    async stats() { // APP ROLE: db.stats()
      const s = await db.stats();
      return { estimatedBytes: (s && s.dataSize) || 0 };
    },
    async close() {
      // Close only what THIS instance opened. A uriOverride (prune-role)
      // connection is never the cached app singleton — always close it
      // directly and never read/clear `cached`, so closing a prune repo can
      // never disturb (or be confused with) the app's warm connection.
      if (uriOverride) { await client.close(); return; }
      if (cached) { await cached.client.close(); cached = null; }
    },
  };
}

module.exports = { createMongoRepo };
