'use strict';
// Server-minted export watermark + import tracing (spec §5 watermarks, §6.4).
//
// On an authorized export the server mints a watermarkId and records the export
// origin. When that artifact is later imported, the import is recorded against
// the same watermarkId, so an admin can trace an export to every import of it.
//
// Storage note: imports live in their OWN collection (watermarkImports), not an
// embedded array, to avoid the embedded-array lost-update race and the 16MB
// document-growth cap. The importer's IP is stored encrypted (record-bound AAD)
// + blind-indexed, mirroring audit events — admin-decryptable, never plaintext.

const crypto = require('crypto');
const netip = require('./netip');
const anomaly = require('./anomaly');
const { httpError } = require('./errors');

function importAad(watermarkId, userId) {
  return `wmi:${watermarkId}:${userId}`;
}

// Mint a watermark for an authorized export. Idempotent on the export's
// idempotency key: a retry returns the SAME watermark (no orphan docs).
async function mint(ctx, { userId, deviceId, fileSha256, idempotencyKey }) {
  if (idempotencyKey) {
    const existing = await ctx.repo.watermarks.findOne({ mintKey: idempotencyKey });
    if (existing) return existing;
  }
  const watermarkId = crypto.randomUUID();
  return ctx.repo.watermarks.insert({
    _id: watermarkId,
    exportUserId: userId,
    exportDeviceId: deviceId || null,
    exportedAt: ctx.clock.now(),
    fileSha256: fileSha256 || null,
    mintKey: idempotencyKey || null,
  });
}

// Record an import against a watermark. Identity is SERVER-STAMPED (never from
// client params). Deduped by (watermarkId,userId,deviceId,fileSha256) so a
// retried/looped import never inflates the tracer.
async function recordImport(ctx, { watermarkId, userId, deviceId, ip, fileSha256 }) {
  const sha = fileSha256 || null;
  const dedupeKey = `${watermarkId}:${userId}:${deviceId || ''}:${sha || ''}`;
  const record = await resolveImportRecord(ctx, { watermarkId, userId, deviceId, ip, sha, dedupeKey });
  // Leak alarm: the SAME watermarkId being imported by a user other than its
  // exporter is a cross-user disclosure — alert, never block (the import above
  // has already succeeded). idempotencyKey is derived from the deterministic
  // import dedupeKey (NOT the caller's idempotency-key header), so replays of
  // the same recorded import — via any path that lands on the same
  // (watermarkId,userId,deviceId,fileSha256) — collapse to one anomaly.
  await flagCrossUserImport(ctx, { watermarkId, userId, deviceId, ip, dedupeKey });
  return record;
}

async function resolveImportRecord(ctx, { watermarkId, userId, deviceId, ip, sha, dedupeKey }) {
  const existing = await ctx.repo.watermarkImports.findOne({ dedupeKey });
  if (existing) return existing;
  const { ipEnc, ipIdx } = netip.encryptIp(ctx, ip, importAad(watermarkId, userId));
  try {
    return await ctx.repo.watermarkImports.insert({
      watermarkId, userId, deviceId: deviceId || null,
      ipEnc, ipIdx, fileSha256: sha, at: ctx.clock.now(), dedupeKey,
    });
  } catch (err) {
    // A concurrent identical import lost the unique-index race — return the
    // winner instead of surfacing a 500 (mirrors users.createUser). Deduped to
    // one tracer row on BOTH the in-memory and Mongo repos.
    if (err && err.code === 'DUPLICATE_WMI') {
      const won = await ctx.repo.watermarkImports.findOne({ dedupeKey });
      if (won) return won;
    }
    throw err;
  }
}

async function flagCrossUserImport(ctx, { watermarkId, userId, deviceId, ip, dedupeKey }) {
  const wm = await ctx.repo.watermarks.findById(watermarkId);
  if (!wm || wm.exportUserId === userId) return; // unknown watermark, or the exporter re-importing their own file
  await anomaly.emit(ctx, {
    severity: 'critical',
    userId, deviceId, ip,
    reason: anomaly.REASONS.CROSS_USER_IMPORT,
    watermarkId,
    exportUserId: wm.exportUserId,
    dedupeKey: `anomaly:cross_user_import:${dedupeKey}`,
  });
}

// Trace an export → all recorded imports of it. The caller must be admin (route
// is admin-gated); the importer IP is decrypted for the admin view.
async function trace(ctx, watermarkId) {
  const wm = await ctx.repo.watermarks.findById(watermarkId);
  if (!wm) throw httpError(404, 'Watermark not found.');
  const imports = await ctx.repo.watermarkImports.find({ watermarkId });
  return {
    watermarkId,
    export: {
      userId: wm.exportUserId,
      deviceId: wm.exportDeviceId,
      exportedAt: wm.exportedAt,
      fileSha256: wm.fileSha256,
    },
    imports: imports
      .sort((a, b) => new Date(a.at) - new Date(b.at))
      .map(i => ({
        userId: i.userId,
        deviceId: i.deviceId,
        at: i.at,
        ip: i.ipEnc ? safeDecrypt(ctx, i.ipEnc, importAad(i.watermarkId, i.userId)) : null,
      })),
  };
}

function safeDecrypt(ctx, ipEnc, aad) {
  try { return netip.decryptIp(ctx, ipEnc, aad); } catch { return null; }
}

// Browse recent export→import flows (no watermarkId required). Newest export
// first, capped to `limit`. Metadata only — never file contents — and the
// importer IP is decrypted here for the admin view only (same helpers as
// trace(), never a duplicated AAD string).
async function recentTransfers(ctx, { sinceMs, limit = 200 }) {
  const since = new Date(sinceMs);
  const wms = await ctx.repo.watermarks.find({ exportedAt: { $gte: since } });
  const sorted = wms
    .sort((a, b) => new Date(b.exportedAt) - new Date(a.exportedAt))
    .slice(0, limit);
  const out = [];
  for (const wm of sorted) {
    const imports = await ctx.repo.watermarkImports.find({ watermarkId: wm._id });
    const sortedImports = imports
      .sort((a, b) => new Date(a.at) - new Date(b.at))
      .map(i => ({
        userId: i.userId,
        deviceId: i.deviceId,
        at: i.at,
        ip: i.ipEnc ? safeDecrypt(ctx, i.ipEnc, importAad(i.watermarkId, i.userId)) : null,
      }));
    out.push({
      watermarkId: wm._id,
      export: {
        userId: wm.exportUserId,
        deviceId: wm.exportDeviceId,
        exportedAt: wm.exportedAt,
        fileSha256: wm.fileSha256,
      },
      imports: sortedImports,
      importCount: sortedImports.length,
    });
  }
  return out;
}

module.exports = { mint, recordImport, trace, recentTransfers };
