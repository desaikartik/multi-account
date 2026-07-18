'use strict';
// Admin reporting APIs (spec §8). Every report is:
//   - ADMIN-ROLE-GATED SERVER-SIDE — the route carries admin:true AND each
//     function re-checks requireAdmin (defense in depth), so a member can never
//     read another member's data.
//   - 7-DAY WINDOWED — the window is clamped server-side to [1,7] days
//     (Addendum B retention), so no caller can widen it.
// A userId argument is only ever an admin-scoped FILTER, never the caller's own
// identity. Encrypted IPs are decrypted for the admin view (admin-only).

const netip = require('./netip');
const { requireAdmin } = require('./entitlements');
const watermark = require('./watermark');
const { decryptEmail } = require('./users');
const { REASON_LABELS } = require('./anomaly');

const M0_BYTES = 512 * 1024 * 1024;

function clampDays(days) {
  const n = Number(days);
  if (!Number.isFinite(n)) return 7;
  return Math.min(7, Math.max(1, Math.floor(n)));
}

function cutoff(ctx, days) {
  return new Date(ctx.clock.nowMs() - clampDays(days) * 24 * 60 * 60 * 1000);
}

function safeDecrypt(ctx, ipEnc, recordCtx) {
  if (!ipEnc) return null;
  try { return netip.decryptIp(ctx, ipEnc, recordCtx); } catch { return null; }
}

// Resolve a set of userIds -> email ONCE (admin-only PII; per-user decrypt with
// try/catch -> null, exactly like usersDirectory/usageOverview/transferFlows).
// Returns a Map so callers can attach a human-readable email wherever a raw
// userId would otherwise be shown (devices, timeline, ...).
async function emailByUserId(ctx, userIds) {
  const map = new Map();
  for (const uid of userIds) {
    if (uid == null || map.has(uid)) continue;
    let email = null;
    try {
      const u = await ctx.repo.users.findById(uid);
      if (u) { try { email = decryptEmail(ctx, u); } catch { email = null; } }
    } catch { /* leave email null */ }
    map.set(uid, email);
  }
  return map;
}

async function activityTimeline(ctx, { adminId, userId, days = 7 }) {
  await requireAdmin(ctx, adminId);
  const filter = { serverTs: { $gte: cutoff(ctx, days) } };
  if (userId) filter.userId = userId; // admin-scoped filter, not caller identity
  const events = await ctx.repo.auditEvents.find(filter);
  const emails = await emailByUserId(ctx, events.map(e => e.userId));
  return {
    windowDays: clampDays(days),
    events: events.map(e => ({
      seq: e.seq, serverTs: e.serverTs, eventType: e.eventType, severity: e.severity,
      userId: e.userId || null, email: (e.userId != null ? emails.get(e.userId) : null) || null,
      deviceId: e.deviceId || null, result: e.result || null,
      reason: e.reason || null, watermarkId: e.watermarkId || null, geo: e.geo || null,
      ip: safeDecrypt(ctx, e.ipEnc, e.userId),
    })),
  };
}

async function deviceInventory(ctx, { adminId }) {
  await requireAdmin(ctx, adminId);
  const devices = await ctx.repo.devices.find({});
  const emails = await emailByUserId(ctx, devices.map(d => d.userId));
  return {
    devices: devices.map(d => ({
      deviceId: d._id, userId: d.userId || null, email: (d.userId != null ? emails.get(d.userId) : null) || null,
      status: d.status || 'active',
      firstSeen: d.firstSeen || null, lastSeen: d.lastSeen || null,
      appVersion: d.appVersion || null, os: d.os || null,
      // Primary (v4-preferred) + BOTH families from the client heartbeat, so the
      // admin sees who is connecting from where over both IPv4 and IPv6.
      lastIp: safeDecrypt(ctx, d.lastIpEnc, `device:${d._id}`),
      geo: d.lastGeo || null,
      ipv4: safeDecrypt(ctx, d.lastIpv4Enc, `device:${d._id}`),
      geo4: d.lastGeo4 || null,
      ipv6: safeDecrypt(ctx, d.lastIpv6Enc, `device:${d._id}`),
      geo6: d.lastGeo6 || null,
    })),
  };
}

// Detail enrichment (REPORT-ONLY, additive — never touches audit.recordEvent
// / CORE_FIELDS / the hash chain): resolves each distinct affected userId to
// an email (once each, mirroring usersDirectory's per-user decrypt try/catch)
// plus a human-readable reasonLabel and an alertsMuted flag, so an admin can
// see at a glance "whose alert, what happened, was the email suppressed".
async function alertsFeed(ctx, { adminId, days = 7 }) {
  await requireAdmin(ctx, adminId);
  const events = await ctx.repo.auditEvents.find({
    serverTs: { $gte: cutoff(ctx, days) },
    severity: { $in: ['warn', 'critical'] },
  });

  const userIds = new Set();
  for (const e of events) {
    if (e.userId != null) userIds.add(e.userId);
  }
  const userInfo = new Map();
  for (const uid of userIds) {
    let email = null;
    let alertsMuted = false;
    try {
      const u = await ctx.repo.users.findById(uid);
      if (u) {
        try { email = decryptEmail(ctx, u); } catch { email = null; }
        alertsMuted = u.alertsEnabled === false;
      }
    } catch { /* leave email null, alertsMuted false */ }
    userInfo.set(uid, { email, alertsMuted });
  }

  return {
    windowDays: clampDays(days),
    alerts: events.map(e => {
      const info = e.userId != null ? userInfo.get(e.userId) : null;
      return {
        seq: e.seq, serverTs: e.serverTs, severity: e.severity, eventType: e.eventType,
        reason: e.reason || null, userId: e.userId || null, deviceId: e.deviceId || null,
        email: info ? info.email : null,
        reasonLabel: (e.reason && REASON_LABELS[e.reason]) || e.reason || null,
        alertsMuted: info ? info.alertsMuted : false,
      };
    }),
  };
}

async function storagePercent(ctx, { adminId }) {
  await requireAdmin(ctx, adminId);
  const { estimatedBytes } = await ctx.repo.stats();
  const percent = Math.max(0, Math.min(100, (estimatedBytes / M0_BYTES) * 100));
  return { estimatedBytes, capacityBytes: M0_BYTES, percent };
}

// Admin browse feed over recent export→import provenance (who exported, who
// imported, where/when) — metadata only, never file contents. Day-windowed +
// clamped like every other report (Addendum B retention).
async function transferFlows(ctx, { adminId, days = 7 }) {
  await requireAdmin(ctx, adminId);
  const sinceMs = cutoff(ctx, days).getTime();
  const transfers = await watermark.recentTransfers(ctx, { sinceMs });

  // Resolve every referenced userId -> email ONCE (admin-only PII, same
  // per-user decrypt/try-catch pattern as usageOverview/usersDirectory), so the
  // feed reads "exported by <email> ... imported by <email>" instead of raw ids.
  const userIds = new Set();
  for (const t of transfers) {
    if (t.export && t.export.userId != null) userIds.add(t.export.userId);
    for (const imp of (t.imports || [])) if (imp && imp.userId != null) userIds.add(imp.userId);
  }
  const emailByUser = new Map();
  for (const uid of userIds) {
    let email = null;
    try {
      const u = await ctx.repo.users.findById(uid);
      if (u) { try { email = decryptEmail(ctx, u); } catch { email = null; } }
    } catch { /* leave email null */ }
    emailByUser.set(uid, email);
  }

  const withEmails = transfers.map(t => ({
    ...t,
    export: { ...(t.export || {}), email: (t.export && emailByUser.get(t.export.userId)) || null },
    imports: (t.imports || []).map(imp => ({ ...imp, email: (imp && emailByUser.get(imp.userId)) || null })),
  }));
  return { transfers: withEmails };
}

// Admin usage-tracking fleet overview (spec f1a-usage-backend): "who used
// how much of each Claude account's limits and when." Reads the additive
// usage_snapshots collection (lib/usagestore.js — updated in place, NOT the
// audit ledger). userId here IS an admin-scoped filter target for the join,
// never the caller's own identity (unlike usagestore.myUsage, which is why
// this stays in reporting.js and myUsage does not). Joins userId->email once
// (decryptEmail, per-user try/catch->null, exactly like usersDirectory above)
// and decrypts each row's admin-only account label (try/catch->null, never
// throws). Sort is deterministic and null-safe: heaviest sevenDay first, then
// heaviest fiveHour — never Date.now()/random.
async function usageOverview(ctx, { adminId, days = 7 }) {
  await requireAdmin(ctx, adminId);

  const snapshots = await ctx.repo.usageSnapshots.find({ updatedAt: { $gte: cutoff(ctx, days) } });

  const userIds = new Set();
  for (const s of snapshots) {
    if (s.userId != null) userIds.add(s.userId);
  }
  const emailByUser = new Map();
  for (const uid of userIds) {
    let email = null;
    try {
      const u = await ctx.repo.users.findById(uid);
      if (u) { try { email = decryptEmail(ctx, u); } catch { email = null; } }
    } catch { /* leave email null */ }
    emailByUser.set(uid, email);
  }

  const rows = snapshots.map(s => {
    let accountLabel = null;
    try { accountLabel = ctx.crypto.decrypt(s.labelEnc, 'usage:' + s._id); } catch { accountLabel = null; }
    return {
      userId: s.userId || null,
      email: (s.userId != null ? emailByUser.get(s.userId) : null) || null,
      accountLabel,
      accountUuid: s.accountUuid || null,
      organizationUuid: s.organizationUuid || null,
      fiveHour: s.fiveHour == null ? null : s.fiveHour,
      sevenDay: s.sevenDay == null ? null : s.sevenDay,
      fiveHourResetsAt: s.fiveHourResetsAt || null,
      sevenDayResetsAt: s.sevenDayResetsAt || null,
      capturedAt: s.capturedAt || null,
      updatedAt: s.updatedAt || null,
    };
  });

  // Deterministic, null-safe heaviest-first sort: sevenDay desc, then
  // fiveHour desc. A null percent sorts as lowest (never reported = lightest).
  rows.sort((a, b) => {
    const bs7 = b.sevenDay == null ? -1 : b.sevenDay;
    const as7 = a.sevenDay == null ? -1 : a.sevenDay;
    if (bs7 !== as7) return bs7 - as7;
    const bs5 = b.fiveHour == null ? -1 : b.fiveHour;
    const as5 = a.fiveHour == null ? -1 : a.fiveHour;
    return bs5 - as5;
  });

  return { windowDays: clampDays(days), rows };
}

// Admin users directory (Addendum: "every user by email, with a per-user
// ISSUES list"). Additive/read-only — joins two other 7-day-windowed
// collections (devices, recent warn/critical alerts) onto the full user list
// once each (not per-user queries), then computes a human-readable `issues`
// list per user so an admin can scan "who has a problem" at a glance.
// Sort is deterministic: users WITH issues first (most issues first), then by
// email ascending — never Date.now()/random, so results are stable in tests.
async function usersDirectory(ctx, { adminId }) {
  await requireAdmin(ctx, adminId);

  const allUsers = await ctx.repo.users.find({});

  // Devices joined once, grouped by userId → { count, lastSeen (max) }.
  const devices = await ctx.repo.devices.find({});
  const deviceStats = new Map();
  for (const d of devices) {
    if (!d.userId) continue;
    const stat = deviceStats.get(d.userId) || { count: 0, lastSeen: null };
    stat.count += 1;
    if (d.lastSeen && (!stat.lastSeen || new Date(d.lastSeen).getTime() > new Date(stat.lastSeen).getTime())) {
      stat.lastSeen = d.lastSeen;
    }
    deviceStats.set(d.userId, stat);
  }

  // Recent (7-day) warn/critical alerts joined once, grouped by userId → count.
  const recentAlerts = await ctx.repo.auditEvents.find({
    serverTs: { $gte: cutoff(ctx, 7) },
    severity: { $in: ['warn', 'critical'] },
  });
  const alertCounts = new Map();
  for (const e of recentAlerts) {
    if (!e.userId) continue;
    alertCounts.set(e.userId, (alertCounts.get(e.userId) || 0) + 1);
  }

  // Pre-decrypt every user's email ONCE into a Map (F3 provenance): this is
  // the SAME per-user decrypt work the row loop below already did inline —
  // just hoisted so createdByEmail can join a creator's email regardless of
  // where that creator sorts in allUsers, with ZERO extra reads/decrypts.
  const emailById = new Map();
  for (const u of allUsers) {
    let email = null;
    try { email = decryptEmail(ctx, u); } catch { email = null; }
    emailById.set(u._id, email);
  }

  const rows = allUsers.map(u => {
    const email = emailById.get(u._id);

    const deviceStat = deviceStats.get(u._id) || { count: 0, lastSeen: null };
    const openAlerts = alertCounts.get(u._id) || 0;
    const monitoringEnabled = u.monitoringEnabled !== false;
    const entitlementExpired = (u.entitlementExpiresAt && new Date(u.entitlementExpiresAt).getTime() < ctx.clock.nowMs()) || false;
    const geoFenceCountries = (u.geoFence && Array.isArray(u.geoFence.countries)) ? u.geoFence.countries : [];
    const blockedCountries = (u.blockedCountries && Array.isArray(u.blockedCountries.countries)) ? u.blockedCountries.countries : [];

    const issues = [];
    if (u.status === 'suspended') issues.push('Suspended');
    if (u.status === 'deprovisioned') issues.push('Deprovisioned');
    if (u.status === 'pending') issues.push('Awaiting approval');
    if (u.status === 'rejected') issues.push('Rejected');
    if (entitlementExpired) issues.push('Access expired');
    if (!monitoringEnabled) issues.push('Monitoring paused');
    if (geoFenceCountries.length) issues.push('Geo-fenced');
    if (blockedCountries.length) issues.push('Country-blocked');
    if (openAlerts > 0) issues.push(`${openAlerts} open alert(s)`);
    if (!u.noticeAcceptedAt) issues.push('Notice not accepted');

    return {
      userId: u._id,
      email,
      role: u.role,
      status: u.status,
      emailVerified: !!u.emailVerified,
      importEnabled: !!u.importEnabled,
      exportEnabled: !!u.exportEnabled,
      monitoringEnabled,
      entitlementExpiresAt: u.entitlementExpiresAt || null,
      entitlementExpired,
      geoFenceCountries,
      blockedCountries,
      noticeAcceptedAt: u.noticeAcceptedAt || null,
      createdAt: u.createdAt || null,
      createdBy: u.createdBy || null,
      createdByEmail: (u.createdBy && emailById.get(u.createdBy)) || null,
      deviceCount: deviceStat.count,
      lastSeen: deviceStat.lastSeen,
      openAlerts,
      issues,
    };
  });

  // Deterministic sort: issues.length desc, then email asc (stable — no
  // Date.now()/random). A null email (decrypt failure) sorts as '' (first).
  rows.sort((a, b) => {
    if (b.issues.length !== a.issues.length) return b.issues.length - a.issues.length;
    const ae = a.email || '';
    const be = b.email || '';
    if (ae < be) return -1;
    if (ae > be) return 1;
    return 0;
  });

  return { users: rows };
}

module.exports = { activityTimeline, deviceInventory, alertsFeed, storagePercent, transferFlows, usersDirectory, usageOverview };
