'use strict';
// Usage tracking store (additive, storage-lean) — spec: f1a-usage-backend.
//
// NOT the audit ledger: usage snapshots are never audit events, never touch
// CORE_FIELDS or the hash chain (audit.js), and are stored in their own
// `usage_snapshots` collection (repo.js / mongoRepo.js).
//
// Storage model (one doc per (user,account), UPDATED IN PLACE — mirrors the
// devices/heartbeat 512MB-budget pattern in presence.js, not a per-snapshot
// row): deterministic `_id = userId + '|' + accountUuid + '::' + organizationUuid`,
// holding the LATEST snapshot (for the fleet overview) plus a capped, hourly-
// bucketed `series` (for "usage over time"). The series is trimmed to `cap`
// entries on every write, so storage is bounded by users x accounts, not by
// time — no unbounded per-beat growth.
//
// Kept OUT of reporting.js on purpose: reporting.js's documented invariant is
// "a userId argument is only ever an admin-scoped FILTER, never the caller's
// own identity" — myUsage()'s userId IS the caller (self-scoped read), which
// would violate that invariant if it lived there. reporting.js's
// usageOverview() (the admin fleet view) is the admin-scoped counterpart and
// reads this same collection.

const MAX_ACCOUNTS = 50;
const SERIES_CAP = 168; // ~7 days of hourly buckets
const BUCKET_MS = 3600000; // 1 hour

// clampPct(v): null/undefined pass through as null (no value reported).
// Any other value is coerced with Number(); a non-finite result (bad string,
// object, array, NaN, ±Infinity) also maps to null — never thrown, never
// stored verbatim. A finite number is clamped to [0,100].
function clampPct(v) {
  if (v === null || v === undefined) return null;
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return Math.min(100, Math.max(0, n));
}

function bucketOf(ms, bucketMs) {
  return Math.floor(ms / bucketMs);
}

// mergeSeries(prevSeries, point, nowMs, {cap, bucketMs}) → NEW array (pure —
// never mutates prevSeries or its entries). `point` is {t, s5, s7}. If nowMs
// falls in the same hour-bucket as the last stored point, that point is
// REPLACED (one row per hour, not one per write); otherwise `point` is
// appended. The result is trimmed to the newest `cap` entries.
function mergeSeries(prevSeries, point, nowMs, opts = {}) {
  const cap = opts.cap || SERIES_CAP;
  const bucketMs = opts.bucketMs || BUCKET_MS;
  const series = Array.isArray(prevSeries) ? prevSeries.map(p => ({ ...p })) : [];
  const newPoint = { t: point.t, s5: point.s5 == null ? null : point.s5, s7: point.s7 == null ? null : point.s7 };

  if (series.length > 0 && bucketOf(nowMs, bucketMs) === bucketOf(series[series.length - 1].t, bucketMs)) {
    series[series.length - 1] = newPoint;
  } else {
    series.push(newPoint);
  }

  if (series.length > cap) series.splice(0, series.length - cap); // keep the newest `cap`
  return series;
}

function usageId(userId, accountUuid, organizationUuid) {
  return `${userId}|${accountUuid}::${organizationUuid}`;
}

function labelAad(id) {
  return 'usage:' + id;
}

// recordUsageSnapshot(ctx, {userId, accounts}): batch upsert-in-place, one doc
// per (userId, accountUuid, organizationUuid). `userId` is ALWAYS the ctx-
// supplied caller identity (from the verified access token in routes.js) —
// any `userId` a client sneaks into an account entry is simply never read, so
// it can never spoof another user's row. `accounts` is capped to MAX_ACCOUNTS
// (defense against an unbounded batch); each pct is clamped via clampPct;
// the account label is encrypted at rest (AAD bound to the doc's own _id, so
// a ciphertext cannot be silently relocated to a different row).
async function recordUsageSnapshot(ctx, { userId, accounts }) {
  const list = Array.isArray(accounts) ? accounts.slice(0, MAX_ACCOUNTS) : [];
  const now = ctx.clock.now();
  const nowMs = ctx.clock.nowMs();
  let recorded = 0;

  for (const raw of list) {
    const a = raw || {};
    if (!a.accountUuid || !a.organizationUuid) continue; // malformed entry — skip, never throw
    const _id = usageId(userId, a.accountUuid, a.organizationUuid);
    const existing = await ctx.repo.usageSnapshots.findById(_id);

    const fiveHour = clampPct(a.fiveHour);
    const sevenDay = clampPct(a.sevenDay);
    const point = { t: nowMs, s5: fiveHour, s7: sevenDay };
    const series = mergeSeries(existing ? existing.series : [], point, nowMs, { cap: SERIES_CAP, bucketMs: BUCKET_MS });

    const fields = {
      userId,
      accountUuid: a.accountUuid,
      organizationUuid: a.organizationUuid,
      labelEnc: ctx.crypto.encrypt(String(a.label || ''), labelAad(_id)),
      fiveHour,
      sevenDay,
      fiveHourResetsAt: a.fiveHourResetsAt || null,
      sevenDayResetsAt: a.sevenDayResetsAt || null,
      capturedAt: a.capturedAt || null,
      updatedAt: now,
      series,
    };

    if (existing) {
      await ctx.repo.usageSnapshots.updateById(_id, fields);
    } else {
      await ctx.repo.usageSnapshots.insert({ _id, firstSeen: now, ...fields });
    }
    recorded++;
  }

  return { recorded };
}

function clampDays(days) {
  const n = Number(days);
  if (!Number.isFinite(n)) return 7;
  return Math.min(7, Math.max(1, Math.floor(n)));
}

function cutoff(ctx, days) {
  return new Date(ctx.clock.nowMs() - clampDays(days) * 24 * 60 * 60 * 1000);
}

// myUsage(ctx, {userId, days}): the CALLER'S OWN docs only — userId here is
// the authenticated caller's identity (never an admin-supplied filter; see
// the module header). Windowed by updatedAt, decrypts each account's own
// label (try/catch → null, never throws), and includes the capped series.
async function myUsage(ctx, { userId, days }) {
  const docs = await ctx.repo.usageSnapshots.find({ userId, updatedAt: { $gte: cutoff(ctx, days) } });
  const accounts = docs.map(d => {
    let label = null;
    try { label = ctx.crypto.decrypt(d.labelEnc, labelAad(d._id)); } catch { label = null; }
    return {
      accountUuid: d.accountUuid,
      organizationUuid: d.organizationUuid,
      label,
      fiveHour: d.fiveHour == null ? null : d.fiveHour,
      sevenDay: d.sevenDay == null ? null : d.sevenDay,
      fiveHourResetsAt: d.fiveHourResetsAt || null,
      sevenDayResetsAt: d.sevenDayResetsAt || null,
      capturedAt: d.capturedAt || null,
      updatedAt: d.updatedAt,
      series: d.series || [],
    };
  });
  return { windowDays: clampDays(days), accounts };
}

module.exports = {
  clampPct, mergeSeries, recordUsageSnapshot, myUsage,
  usageId, labelAad, clampDays, cutoff,
  MAX_ACCOUNTS, SERIES_CAP, BUCKET_MS,
};
