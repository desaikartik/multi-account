'use strict';
// Export / import AUTHORIZE — the server-side enforcement point for data
// transfer (spec §6.4, §7). The client's UI gate is cosmetic; the real decision
// is made here on every call (CWE-602):
//
//   export/authorize → live entitlement check (assertCan) → daily quota →
//                      mint watermark → `export` audit event.  Denied → an
//                      `export_denied` event + a non-entitled anomaly.
//   import/authorize → live entitlement check → record the import against its
//                      watermark → `import` audit event. Denied likewise.
//
// Idempotent: a retried authorize (same idempotency key) returns the original
// decision WITHOUT re-charging quota or minting a second watermark.

const entitlements = require('./entitlements');
const watermark = require('./watermark');
const audit = require('./audit');
const anomaly = require('./anomaly');
const { httpError } = require('./errors');

const DAY_MS = 24 * 60 * 60 * 1000;

function hourBucket(ctx) {
  return Math.floor(ctx.clock.nowMs() / (60 * 60 * 1000));
}

// Enforce the daily export quota. maxPerDay === 0 means "no explicit cap" (the
// entitlement flag is the gate); > 0 enforces a rolling 24h cap with rollover.
async function enforceExportQuota(ctx, userId) {
  const user = await ctx.repo.users.findById(userId);
  const q = user.exportQuota || { maxPerDay: 0, used: 0, windowStart: ctx.clock.now() };
  if (!q.maxPerDay || q.maxPerDay <= 0) return;
  const now = ctx.clock.now();
  let used = q.used || 0;
  let windowStart = q.windowStart ? new Date(q.windowStart) : now;
  if (now.getTime() - windowStart.getTime() >= DAY_MS) { used = 0; windowStart = now; }
  if (used >= q.maxPerDay) throw httpError(429, 'Daily export limit reached.');
  await ctx.repo.users.updateById(userId, {
    exportQuota: { maxPerDay: q.maxPerDay, used: used + 1, windowStart }, updatedAt: now,
  });
}

async function authorizeExport(ctx, { userId, deviceId, ip, fileMeta, idempotencyKey }) {
  // Idempotency short-circuit BEFORE quota so a retry never double-charges.
  if (idempotencyKey) {
    const existing = await ctx.repo.auditEvents.findByIdempotencyKey(idempotencyKey);
    if (existing) return { watermarkId: existing.watermarkId, idempotent: true };
  }
  try {
    await entitlements.assertCan(ctx, userId, 'export');
  } catch (err) {
    await audit.recordEvent(ctx, {
      eventType: 'export_denied', userId, deviceId, ip, result: 'denied', fileMeta,
      idempotencyKey: idempotencyKey ? `${idempotencyKey}:denied` : undefined,
    });
    await anomaly.emit(ctx, {
      severity: 'warn', userId, deviceId, ip, reason: anomaly.REASONS.EXPORT_NOT_ENTITLED,
      dedupeKey: `anomaly:export_not_entitled:${userId}:${hourBucket(ctx)}`,
    });
    throw err;
  }
  await enforceExportQuota(ctx, userId);
  const fileSha256 = fileMeta && fileMeta.sha256 ? fileMeta.sha256 : null;
  const wm = await watermark.mint(ctx, { userId, deviceId, fileSha256, idempotencyKey });
  await audit.recordEvent(ctx, {
    eventType: 'export', userId, deviceId, ip, result: 'allowed', fileMeta,
    watermarkId: wm._id, idempotencyKey,
  });
  return { watermarkId: wm._id, idempotent: false };
}

async function authorizeImport(ctx, { userId, deviceId, ip, watermarkId, fileMeta, idempotencyKey }) {
  if (idempotencyKey) {
    const existing = await ctx.repo.auditEvents.findByIdempotencyKey(idempotencyKey);
    if (existing) return { ok: true, idempotent: true };
  }
  try {
    await entitlements.assertCan(ctx, userId, 'import');
  } catch (err) {
    await audit.recordEvent(ctx, {
      eventType: 'import_denied', userId, deviceId, ip, result: 'denied', fileMeta,
      idempotencyKey: idempotencyKey ? `${idempotencyKey}:denied` : undefined,
    });
    await anomaly.emit(ctx, {
      severity: 'warn', userId, deviceId, ip, reason: anomaly.REASONS.IMPORT_NOT_ENTITLED,
      dedupeKey: `anomaly:import_not_entitled:${userId}:${hourBucket(ctx)}`,
    });
    throw err;
  }
  const fileSha256 = fileMeta && fileMeta.sha256 ? fileMeta.sha256 : null;
  if (watermarkId) {
    await watermark.recordImport(ctx, { watermarkId, userId, deviceId, ip, fileSha256 });
  }
  await audit.recordEvent(ctx, {
    eventType: 'import', userId, deviceId, ip, result: 'allowed', fileMeta,
    watermarkId: watermarkId || null, idempotencyKey,
  });
  return { ok: true, idempotent: false };
}

module.exports = { authorizeExport, authorizeImport, enforceExportQuota };
