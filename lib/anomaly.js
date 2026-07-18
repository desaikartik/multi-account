'use strict';
// Anomaly engine. Emits SERVER-AUTHORED `anomaly` audit events (severity
// warn|critical) and, for a NEW incident, an admin email alert.
//
// DEDUP (serverless-safe): the caller passes a deterministic `dedupeKey`; it
// becomes the audit event's idempotencyKey, so a repeated condition collapses to
// ONE ledger row (the repo's unique index enforces this even across serverless
// cold starts and scheduler ticks). The admin email is sent ONLY when the event
// was newly recorded (res.idempotent === false), so one incident = one email.
//
// FAIL-OPEN ON LOGGING: emit() never throws into the caller. A DB/mailer hiccup
// while logging an anomaly must not break the user's actual request. Access
// decisions (block / geo-fence / entitlement) are made upstream and are
// independent of emit() succeeding.

const audit = require('./audit');
const usersLib = require('./users');
const netip = require('./netip');
const { redactSensitive } = require('./errors');

// Anomaly reason codes (also the human-facing `reason` on the audit event).
const REASONS = {
  IP_BLOCKED: 'ip_blocked',
  IP_NOT_ALLOWLISTED: 'ip_not_allowlisted',
  GEO_FENCED: 'geo_fenced',
  GEO_UNKNOWN_UNDER_FENCE: 'geo_unknown_under_fence',
  GEO_BLOCKED: 'geo_blocked',
  IMPOSSIBLE_TRAVEL: 'impossible_travel',
  NEW_DEVICE: 'new_device',
  DEVICE_OWNERSHIP_CONFLICT: 'device_ownership_conflict',
  IP_MISMATCH: 'ip_mismatch',
  REPEATED_FAILED_LOGINS: 'repeated_failed_logins',
  EXPORT_NOT_ENTITLED: 'export_not_entitled',
  IMPORT_NOT_ENTITLED: 'import_not_entitled',
  CHAIN_VERIFY_FAILED: 'chain_verify_failed',
  DEAD_MAN: 'dead_man',
  CROSS_USER_IMPORT: 'cross_user_import',
};

// Human-facing labels for each REASONS value ("kiska alert, kya" — whose
// alert, what happened). Keyed by the reason STRING VALUE (not the REASONS
// constant name) because that string is what's stored on the audit event and
// returned by reporting.alertsFeed. REPORT-ONLY / additive: consumed by
// reporting.js and the admin view-model builders, never by audit.recordEvent
// or anything in the hash chain. An unmapped or null reason falls back to the
// raw string (or null) at the call site — this map is never required to be
// exhaustive for forward-compatibility with a future reason code.
const REASON_LABELS = {
  ip_blocked: 'Sign-in from a blocked IP address',
  ip_not_allowlisted: 'Sign-in from an IP not on the allowlist',
  geo_fenced: 'Sign-in from a blocked country (geo-fence)',
  geo_unknown_under_fence: 'Sign-in from an unverifiable location while geo-fenced',
  geo_blocked: 'Sign-in from a blacklisted country',
  impossible_travel: 'Impossible travel between two locations',
  new_device: 'Sign-in from a new, unrecognized device',
  device_ownership_conflict: 'A device ID already registered to another user',
  ip_mismatch: 'Reported IP did not match the observed connection',
  repeated_failed_logins: 'Repeated failed sign-in attempts from one IP',
  export_not_entitled: 'Export attempted without permission',
  import_not_entitled: 'Import attempted without permission',
  chain_verify_failed: 'Audit chain verification failed',
  dead_man: 'Device holding credentials has gone silent',
  cross_user_import: 'A file was imported by a different user than exported it',
};

// Resolve active-admin recipient addresses (decrypting emailEnc). Any failure
// (no admins, undecryptable record, DB error) yields [] — never throws.
async function adminRecipients(ctx) {
  try {
    const admins = await ctx.repo.users.find({ role: 'admin', status: 'active' });
    const out = [];
    for (const a of admins) {
      try { out.push(usersLib.decryptEmail(ctx, a)); } catch { /* skip undecryptable */ }
    }
    return out;
  } catch { return []; }
}

async function sendAdminAlert(ctx, { severity, reason, userId, detail }) {
  const to = await adminRecipients(ctx);
  if (!to.length) return; // zero admins → fail open, no email
  await ctx.mailer.send({
    to: to.join(','),
    subject: `[Managed Switcher] ${String(severity).toUpperCase()} alert: ${reason}`,
    text: `A ${severity} anomaly was detected on the managed switcher.\n\n`
      + `Type:   ${reason}\n`
      + `User:   ${userId || 'n/a'}\n`
      + `Detail: ${detail || 'n/a'}\n`
      + `Time:   ${ctx.clock.now().toISOString()} (UTC)\n\n`
      + `Open the admin alerts feed for the full context.`,
  });
}

// Per-user NOTIFICATION preference gate for the admin email only — distinct
// from monitoringEnabled (which stops telemetry COLLECTION at the client).
// The audit event is ALWAYS recorded regardless of this (see emit() below):
// skipping the tamper-evident record would create a forensic gap ("disable my
// alerts, then act unseen"); only the push channel (email) is muted here.
// No userId (an IP-level anomaly, e.g. repeated_failed_logins) always alerts.
// Fail-open on any lookup error/missing user — alert on doubt.
async function alertsEnabledFor(ctx, userId) {
  if (!userId) return true;
  try {
    const u = await ctx.repo.users.findById(userId);
    return !u || u.alertsEnabled !== false;
  } catch {
    return true;
  }
}

// Record an anomaly (deduped) and, for a new incident, alert admins.
// Returns the recordEvent result, or null if logging failed (fail-open).
async function emit(ctx, opts = {}) {
  const {
    severity = 'warn', userId, deviceId, ip, reason,
    dedupeKey, email = true, detail, fileMeta, watermarkId, exportUserId,
  } = opts;
  try {
    const res = await audit.recordEvent(ctx, {
      eventType: 'anomaly',
      severity: severity === 'critical' ? 'critical' : 'warn',
      userId, deviceId, ip, reason, fileMeta, watermarkId, exportUserId,
      idempotencyKey: dedupeKey,
    });
    if (email && res && res.idempotent === false && await alertsEnabledFor(ctx, userId)) {
      // Swallow email errors: a down mailer must not turn logging into a failure.
      await sendAdminAlert(ctx, { severity, reason, userId, detail }).catch((err) => {
        logErr(ctx, 'anomaly alert email failed: ' + (err && err.message));
      });
    }
    return res;
  } catch (err) {
    logErr(ctx, 'anomaly emit failed: ' + (err && err.message));
    return null;
  }
}

// Per-IP failed-login tracker. Incremented UNIFORMLY on every failed-login
// branch (unknown email, wrong password, locked) so it catches credential
// stuffing/spray across many accounts from one source — which a per-user
// counter misses — and simultaneously keeps the branches' work shape equal
// (#17/#19). Emits a deduped anomaly when the per-window threshold is crossed.
// Never throws into the login path (fail-open on logging).
async function recordLoginFailure(ctx, ip) {
  try {
    const canon = netip.canonicalizeIp(ip);
    if (!canon) return;
    const ipIdx = netip.ipIdxOf(ctx, canon);
    const now = ctx.clock.now();
    const windowMs = ctx.config.anomaly.repeatedFailWindowMs;
    const rec = await ctx.repo.loginAttempts.findOne({ ipIdx });
    if (!rec || (now.getTime() - new Date(rec.windowStart).getTime()) >= windowMs) {
      if (rec) await ctx.repo.loginAttempts.updateById(rec._id, { count: 1, windowStart: now });
      else {
        try { await ctx.repo.loginAttempts.insert({ ipIdx, count: 1, windowStart: now }); }
        catch { /* concurrent create race — best-effort counter */ }
      }
      return;
    }
    const count = (rec.count || 0) + 1;
    await ctx.repo.loginAttempts.updateById(rec._id, { count });
    if (count >= ctx.config.anomaly.repeatedFailThreshold) {
      const bucket = Math.floor(now.getTime() / windowMs);
      await emit(ctx, {
        severity: 'warn', ip, reason: REASONS.REPEATED_FAILED_LOGINS,
        detail: `${count} failed logins in the window`,
        dedupeKey: `anomaly:repeated_failed_logins:${ipIdx}:${bucket}`,
      });
    }
  } catch (err) {
    logErr(ctx, 'recordLoginFailure failed: ' + (err && err.message));
  }
}

// Fail-open logging helper: ALWAYS redacts before writing, because these paths
// wrap live DB/mailer ops whose errors can embed the Mongo URI with credentials
// (mirrors the redaction on the request-error path in routes.js).
function logErr(ctx, message) {
  if (ctx.logger && ctx.logger.error) ctx.logger.error(redactSensitive(message));
}

module.exports = { emit, adminRecipients, recordLoginFailure, REASONS, REASON_LABELS, alertsEnabledFor };
