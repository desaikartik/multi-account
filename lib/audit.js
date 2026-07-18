'use strict';
// Tamper-evident audit ledger.
//
//  - Append-only, HMAC hash-chained (via hashchain.js), monotonic seq.
//  - serverTs is the AUTHORITATIVE UTC timestamp (from the injected clock);
//    clientTs is recorded but never trusted for ordering or decisions.
//  - Idempotent ingestion: an event carrying an idempotencyKey is written at
//    most once, so a client that retries after a network timeout never dupes
//    (at-least-once delivery, exactly-once storage).
//  - Daily Ed25519 ANCHOR: signs {seqHigh, headHash} so that even after events
//    are TTL-pruned (7-day retention), the chain up to each anchor stays
//    provable, and a leaked HMAC key alone cannot forge history (the attacker
//    would also need the anchor signing key).
//  - verify() walks the retained events from the last anchor forward and flags
//    any tamper (bad hash, broken link, bad anchor signature, anchor/head
//    divergence).

const crypto = require('crypto');
const hashchain = require('./hashchain');
const netip = require('./netip');
const { coarseGeo } = require('./geo');
const { httpError } = require('./errors');

const AUDIT_DOMAIN = 'audit_events';
const PERM_DOMAIN = 'permission_changes';

const EVENT_TYPES = new Set([
  'login', 'logout', 'switch', 'export', 'import', 'export_denied', 'import_denied',
  'notice_accepted', 'admin_grant', 'admin_revoke', 'anomaly',
  // Remote-command transitions (server-authored only). Distinct types so the
  // ledger can tell wipe from deprovision from force-logout from disable.
  'remote_wipe', 'remote_lock', 'remote_deprovision', 'remote_force_logout', 'remote_disable',
  // Admin self-service password change (Phase 5 Addendum B#7), server-authored only.
  'password_changed',
]);
const SEVERITIES = new Set(['info', 'warn', 'critical']);

// Only these fields are carried into the (chained) event core. Anything else a
// caller passes is dropped, so the ledger shape is stable and hashable.
const CORE_FIELDS = [
  'userId', 'deviceId', 'eventType', 'result', 'severity',
  'ipEnc', 'ipIdx', 'geo', 'identityRef', 'watermarkId', 'exportUserId', 'fileMeta',
  'commandId', 'commandType', 'commandStatus', 'reason', 'auto',
  'clientTs', 'idempotencyKey',
];

// Fields that are SERVER-AUTHORITATIVE and must never be trusted from a caller
// (a client could otherwise fabricate its location in the tamper-evident
// ledger). They are derived here from the raw server-resolved `ip`.
const SERVER_STAMPED = ['ipEnc', 'ipIdx', 'geo'];

// Derive ipEnc/ipIdx (record-bound to userId) + coarse geo from the raw server
// `ip`, and STRIP any client-supplied ipEnc/ipIdx/geo. The raw `ip` itself is
// dropped here so it never reaches the hashed core or any stored/returned field.
async function enrichServerFields(ctx, event) {
  const { ip, ...rest } = event;
  for (const f of SERVER_STAMPED) delete rest[f];
  if (ip) {
    const { ipEnc, ipIdx } = netip.encryptIp(ctx, ip, event.userId);
    if (ipEnc) { rest.ipEnc = ipEnc; rest.ipIdx = ipIdx; }
    if (ctx.geo && typeof ctx.geo.lookup === 'function') {
      try {
        const g = await ctx.geo.lookup(ip);
        const coarse = coarseGeo(g);
        if (coarse) rest.geo = coarse; // {country,region,city,asn} only — never lat/lon
      } catch { /* geo is best-effort; never fails the ingest */ }
    }
  }
  return rest;
}

function buildCore(ctx, event) {
  if (!EVENT_TYPES.has(event.eventType)) throw httpError(400, 'Unknown event type.');
  const severity = event.severity && SEVERITIES.has(event.severity) ? event.severity : 'info';
  const core = { eventType: event.eventType, severity, serverTs: ctx.clock.now() };
  for (const f of CORE_FIELDS) {
    if (f === 'severity') continue;
    if (event[f] !== undefined) core[f] = event[f];
  }
  // clientTs is untrusted: store as an ISO string if provided, else null.
  core.clientTs = event.clientTs != null ? String(event.clientTs) : null;
  return core;
}

async function recordEvent(ctx, event) {
  const key = event.idempotencyKey;
  if (key != null) {
    const existing = await ctx.repo.auditEvents.findByIdempotencyKey(key);
    if (existing) {
      return { seq: existing.seq, serverTs: existing.serverTs, entryHash: existing.entryHash, idempotent: true };
    }
  }
  const enriched = await enrichServerFields(ctx, event);
  const core = buildCore(ctx, enriched);
  try {
    const stored = await hashchain.appendChained(ctx, ctx.repo.auditEvents, ctx.config.auditHmacKey, core, { domain: AUDIT_DOMAIN });
    return { seq: stored.seq, serverTs: stored.serverTs, entryHash: stored.entryHash, idempotent: false };
  } catch (err) {
    // Lost a concurrent race on the same idempotency key → return the winner.
    if (err && err.code === 'DUPLICATE_IDEMPOTENCY') {
      const existing = await ctx.repo.auditEvents.findByIdempotencyKey(key);
      if (existing) {
        return { seq: existing.seq, serverTs: existing.serverTs, entryHash: existing.entryHash, idempotent: true };
      }
    }
    throw err;
  }
}

// --- Anchoring -------------------------------------------------------------

// The signed anchor material is DOMAIN-SEPARATED (like the hash chain, review
// fix #13), so a validly-signed audit anchor is NOT a valid permission_changes
// anchor and vice versa — an attacker with DB write access cannot transplant an
// anchor between the two ledgers to fake tamper-evidence.
function anchorMaterial(domain, seqHigh, headHash) {
  return `anchor|${domain}|${seqHigh}|${headHash}`;
}

function signAnchor(ctx, domain, seqHigh, headHash) {
  return crypto.sign(null, Buffer.from(anchorMaterial(domain, seqHigh, headHash)), ctx.config.anchorPrivateKey).toString('base64');
}

function verifyAnchorSignature(anchorPublicKey, anchor, domain = AUDIT_DOMAIN) {
  try {
    return crypto.verify(
      null,
      Buffer.from(anchorMaterial(domain, anchor.seqHigh, anchor.headHash)),
      anchorPublicKey,
      Buffer.from(anchor.signature, 'base64'),
    );
  } catch {
    return false;
  }
}

// Anchor a chain's head into its anchor collection. No-op (returns the last
// anchor) if the head has not advanced. Generalized so BOTH audit_events and
// permission_changes get their own anchors (closes review gap #3).
async function anchorChain(ctx, { getHead, anchorColl, domain }) {
  const head = await getHead();
  if (!head) return null;
  const anchors = await anchorColl.find({});
  const last = anchors.sort((a, b) => b.seqHigh - a.seqHigh)[0];
  if (last && last.seqHigh === head.seq) return last;
  return anchorColl.insert({
    seqHigh: head.seq,
    headHash: head.entryHash,
    signature: signAnchor(ctx, domain, head.seq, head.entryHash),
    anchoredAt: ctx.clock.now(),
  });
}

async function anchorNow(ctx) {
  return anchorChain(ctx, {
    getHead: () => ctx.repo.auditEvents.getHead(),
    anchorColl: ctx.repo.auditAnchors, domain: AUDIT_DOMAIN,
  });
}

async function anchorPermsNow(ctx) {
  return anchorChain(ctx, {
    getHead: () => ctx.repo.permissionChanges.getHead(),
    anchorColl: ctx.repo.permAnchors, domain: PERM_DOMAIN,
  });
}

// --- Verification ----------------------------------------------------------

// Pure verifier: given the retained events + all anchors, prove integrity.
// Verifies from the last anchor at-or-before the first retained event.
function verifyEvents(events, anchors, { hmacKey, anchorPublicKey, domain = AUDIT_DOMAIN }) {
  // 1. Every anchor's signature must be valid (asymmetric layer) UNDER THIS
  //    LEDGER'S DOMAIN — an anchor from the other ledger fails here. A signed
  //    anchor is a monotonic LOWER BOUND on the head the chain once reached.
  for (const a of anchors) {
    if (!verifyAnchorSignature(anchorPublicKey, a, domain)) {
      return { ok: false, reason: 'anchor_signature_invalid', seqHigh: a.seqHigh };
    }
  }
  const maxAnchorSeq = anchors.reduce((m, a) => Math.max(m, a.seqHigh), 0);
  const sorted = [...events].sort((a, b) => a.seq - b.seq);

  if (sorted.length === 0) {
    // Head-truncation to empty: a signed anchor proves events once existed.
    if (maxAnchorSeq > 0) return { ok: false, reason: 'anchor_ahead_of_head', seqHigh: maxAnchorSeq };
    return { ok: true, count: 0, headSeq: 0 };
  }

  const firstSeq = sorted[0].seq;
  const lastSeq = sorted[sorted.length - 1].seq;

  // 2. Head-truncation: a signed anchor cannot commit to a seq above the head
  //    of the retained chain. (Legitimate pruning removes a prefix, never the
  //    anchored head.) This turns anchors into a real upper-bound guard.
  if (maxAnchorSeq > lastSeq) return { ok: false, reason: 'anchor_ahead_of_head', seqHigh: maxAnchorSeq };

  // 3. Establish a trusted starting checkpoint. firstSeq>1 means a prefix was
  //    pruned; the prune boundary must be exactly an anchor (anchor-aligned
  //    retention — a Phase-2 job), else we cannot trust the tail's prevHash.
  let startSeq = 1;
  let startPrevHash = hashchain.GENESIS;
  if (firstSeq > 1) {
    const startAnchor = anchors.find(a => a.seqHigh === firstSeq - 1);
    if (!startAnchor) return { ok: false, reason: 'no_anchor_for_start', firstSeq };
    startSeq = firstSeq;
    startPrevHash = startAnchor.headHash;
  }

  // 4. Walk + recompute the chain from the checkpoint.
  const walk = hashchain.verifyChain(sorted, hmacKey, { startSeq, startPrevHash, domain });
  if (!walk.ok) return walk;

  // 5. Cross-check anchors inside the retained range against the actual event
  //    head at that seq (defense-in-depth vs a leaked HMAC key).
  const bySeq = new Map(sorted.map(e => [e.seq, e]));
  for (const a of anchors) {
    if (a.seqHigh >= firstSeq && bySeq.has(a.seqHigh)) {
      if (bySeq.get(a.seqHigh).entryHash !== a.headHash) {
        return { ok: false, reason: 'anchor_head_mismatch', seqHigh: a.seqHigh };
      }
    }
  }
  return { ok: true, count: sorted.length, headSeq: walk.headSeq, headHash: walk.headHash };
}

async function verifyAuditChain(ctx) {
  const events = await ctx.repo.auditEvents.find({});
  const anchors = await ctx.repo.auditAnchors.find({});
  return verifyEvents(events, anchors, {
    hmacKey: ctx.config.auditHmacKey,
    anchorPublicKey: ctx.config.anchorPublicKey,
    domain: AUDIT_DOMAIN,
  });
}

// --- Signed compliance export ----------------------------------------------

// Produce a signed, independently-verifiable audit export for a [from,to]
// window. The lower bound is SNAPPED DOWN to an anchor boundary so the exported
// tail starts exactly at an anchor checkpoint (else verifyEvents would return
// no_anchor_for_start). The report is signed with the Ed25519 ANCHOR key — the
// single root of audit trust — so a third party who alters/truncates the report
// cannot re-sign it. Offline verification = check this signature AND re-run
// verifyEvents over the included events+anchors.
async function exportSigned(ctx, { from, to } = {}) {
  const anchors = await ctx.repo.auditAnchors.find({});
  let events = await ctx.repo.auditEvents.find({});
  if (to != null) {
    const toMs = new Date(to).getTime();
    events = events.filter(e => new Date(e.serverTs).getTime() <= toMs);
  }
  if (from != null) {
    const fromMs = new Date(from).getTime();
    const selected = events.filter(e => new Date(e.serverTs).getTime() >= fromMs);
    if (selected.length === 0) {
      events = [];
    } else {
      const firstSeq = selected[0].seq;
      // Snap the start down to (largest anchor below firstSeq).seqHigh + 1.
      const boundary = anchors.filter(a => a.seqHigh < firstSeq).sort((a, b) => b.seqHigh - a.seqHigh)[0];
      const startSeq = boundary ? boundary.seqHigh + 1 : 1;
      events = events.filter(e => e.seq >= startSeq);
    }
  }
  const lastSeq = events.length ? events[events.length - 1].seq : 0;
  // Only include anchors at/below the last exported seq, so the subset is
  // internally consistent (no anchor points above the export's head).
  const inclAnchors = anchors.filter(a => a.seqHigh <= lastSeq);
  const report = {
    kind: 'audit_export',
    generatedAt: ctx.clock.now(),
    from: from != null ? new Date(from) : null,
    to: to != null ? new Date(to) : null,
    count: events.length,
    events,
    anchors: inclAnchors,
  };
  const signature = crypto.sign(null, Buffer.from(hashchain.canonicalJson(report)), ctx.config.anchorPrivateKey).toString('base64');
  return { report, signature };
}

// Independently verify a signed export: the report signature must be valid AND
// the events must form a sound anchor-checked chain. Detects tampering,
// truncation, and reordering (any of which changes canonicalJson → bad sig).
function verifyExport(report, signature, { anchorPublicKey, hmacKey, domain = AUDIT_DOMAIN }) {
  let sigOk = false;
  try {
    sigOk = crypto.verify(null, Buffer.from(hashchain.canonicalJson(report)), anchorPublicKey, Buffer.from(String(signature), 'base64'));
  } catch { sigOk = false; }
  if (!sigOk) return { ok: false, reason: 'report_signature_invalid' };
  return verifyEvents(report.events || [], report.anchors || [], { hmacKey, anchorPublicKey, domain });
}

module.exports = {
  recordEvent, anchorNow, anchorPermsNow, anchorChain,
  verifyAuditChain, verifyEvents, verifyAnchorSignature,
  exportSigned, verifyExport,
  EVENT_TYPES, SEVERITIES, AUDIT_DOMAIN, PERM_DOMAIN,
};
