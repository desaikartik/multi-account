'use strict';
// Route map + transport-agnostic dispatcher.
//
// handleRequest(ctx, req) takes a NORMALIZED request:
//   { method, path, query, headers (lowercased), body, ip }
// and returns { status, body, headers }. Both server.js (Node http) and a
// future Vercel function adapt their transport to this shape, so the exact same
// handlers + security pipeline run in both.
//
// Pipeline order: Host/Origin/Content-Type → auth (+view-scope, +admin) →
// handler → error hygiene. (There is no HTTP-layer request throttle;
// abuse-only controls — login lockout, OTP attempt/send caps, export quota —
// live in their respective service modules and still surface as 429s via
// toErrorResponse.)
//
// Token scopes (see the handleRequest gate). Absence of a `scope` claim = full
// privilege (desktop/CLI/normal login). Two reducing scopes exist:
//   'web'  — POST /auth/web-login mints this. The web console is a FULL-admin
//            console (product decision; only admins can web-login), so 'web' is
//            full admin EXCEPT any route flagged `webDeny: true` (a browser
//            session must never reach those — the decrypted Claude-credential
//            read). scope can only ever REDUCE what a token may do.
//   'view' — a DORMANT read-only scope (Phase 5 Addendum B#6): reaches ONLY
//            routes flagged `webView: true`. No longer minted by web-login, but
//            the flags + gate are kept (unit-tested) for a future viewer role.

const { requestBlockReason } = require('./lib/httpsec');
const { httpError, redactSensitive } = require('./lib/errors');
const tokens = require('./lib/tokens');
const signup = require('./lib/signup');
const authSvc = require('./lib/auth');
const admin = require('./lib/admin');
const entitlements = require('./lib/entitlements');
const audit = require('./lib/audit');
const access = require('./lib/access');
const transfer = require('./lib/transfer');
const watermark = require('./lib/watermark');
const commands = require('./lib/commands');
const reporting = require('./lib/reporting');
const presence = require('./lib/presence');
const devicecreds = require('./lib/devicecreds');
const usagestore = require('./lib/usagestore');

const APP_NAME = 'managed-switcher-backend';
const VERSION = '0.1.0';

const IDEMPOTENCY_HEADER = 'idempotency-key';

// Event types a CLIENT may self-report. Privileged types (admin_grant/revoke,
// remote_wipe/lock, anomaly) are server-authored ONLY and must never be
// accepted from a client, or the ledger's evidentiary value is undermined.
const CLIENT_EVENT_TYPES = new Set([
  'login', 'logout', 'switch', 'export', 'import',
  'export_denied', 'import_denied', 'notice_accepted',
]);

// ---- handlers: (ctx, req) → { status, body } -----------------------------

async function hHealth() {
  return { status: 200, body: { ok: true, app: APP_NAME, version: VERSION } };
}

async function hSignup(ctx, req) {
  const { email, password } = req.body || {};
  const out = await signup.signup(ctx, { email, password });
  return { status: 201, body: out };
}

async function hVerifyEmail(ctx, req) {
  const { email, code } = req.body || {};
  const out = await signup.verifySignup(ctx, { email, code });
  return { status: 200, body: out };
}

async function hLogin(ctx, req) {
  const { email, password, deviceId } = req.body || {};
  const out = await authSvc.login(ctx, { email, password, deviceId, ip: req.ip });
  return { status: 200, body: out };
}

async function hWebLogin(ctx, req) {
  const { email, password, deviceId } = req.body || {};
  const out = await authSvc.webLogin(ctx, { email, password, deviceId, ip: req.ip });
  return { status: 200, body: out };
}

async function hRefresh(ctx, req) {
  const { refreshToken, deviceId } = req.body || {};
  const out = await authSvc.refresh(ctx, { refreshToken, deviceId, ip: req.ip });
  return { status: 200, body: out };
}

async function hLogout(ctx, req) {
  const { refreshToken } = req.body || {};
  const out = await authSvc.logout(ctx, { refreshToken });
  return { status: 200, body: out };
}

// Admin self-service password change (Phase 5 Addendum B#7): re-auth required,
// audited twice, full-scope only — this route deliberately carries NO
// `webView` flag, so a view-scope (web console) bearer is refused before the
// handler ever runs (see the view-scope default-deny check in handleRequest).
async function hChangePassword(ctx, req) {
  const { currentPassword, newPassword } = req.body || {};
  const out = await authSvc.changePassword(ctx, {
    userId: req.auth.userId,
    deviceId: req.auth.deviceId,
    currentPassword,
    newPassword,
    ip: req.ip,
    idempotencyKey: scopedIdempotencyKey(req),
  });
  return { status: 200, body: out };
}

async function hEntitlementsMe(ctx, req) {
  const out = await entitlements.getLiveEntitlements(ctx, req.auth.userId);
  return { status: 200, body: out };
}

async function hAdminSetEntitlement(ctx, req) {
  const { targetUserId, field, value } = req.body || {};
  const out = await entitlements.setEntitlement(ctx, { adminId: req.auth.userId, targetUserId, field, value });
  return { status: 200, body: out };
}

// Admin-side "add employee" (Phase 5/6 admin user management): creates an
// active, email-verified member (or admin) directly — no OTP. This is a
// mutation route and deliberately carries NO `webView` flag, so a view-scope
// (web console) bearer is refused before the handler ever runs (see the
// view-scope default-deny check in handleRequest) — the web console stays
// strictly view-only.
async function hAdminCreateUser(ctx, req) {
  const { email, password, role, importEnabled, exportEnabled, status } = req.body || {};
  const out = await admin.createManagedUser(ctx, {
    adminId: req.auth.userId, email, password, role, importEnabled, exportEnabled, status,
  });
  return { status: 201, body: out };
}

// Approve / reject a pending self-signup (the OTP-free flow). Both are audited
// (setEntitlement -> permission_changes ledger). Full-admin routes; reachable
// from the desktop admin AND the web console (which now mints a full-admin
// token — see auth.webLogin).
async function hApproveUser(ctx, req) {
  const { targetUserId } = req.body || {};
  const out = await admin.approveUser(ctx, { adminId: req.auth.userId, targetUserId });
  return { status: 200, body: out };
}

async function hRejectUser(ctx, req) {
  const { targetUserId } = req.body || {};
  const out = await admin.rejectUser(ctx, { adminId: req.auth.userId, targetUserId });
  return { status: 200, body: out };
}

async function hAuditEvents(ctx, req) {
  const body = req.body || {};
  // Reject privileged/server-only event types from a client (audit forgery).
  if (!CLIENT_EVENT_TYPES.has(body.eventType)) {
    throw httpError(400, 'Unsupported event type.');
  }
  // Scope the idempotency key to the authenticated user so one user's key can
  // never suppress another user's event or echo their entry metadata.
  const rawKey = req.headers[IDEMPOTENCY_HEADER];
  const idempotencyKey = rawKey ? `${req.auth.userId}:${rawKey}` : undefined;
  // Identity + IP/geo are stamped server-side — the client cannot spoof them.
  const out = await audit.recordEvent(ctx, {
    eventType: body.eventType,
    result: body.result,
    clientTs: body.clientTs,
    fileMeta: body.fileMeta,
    reason: body.reason,
    auto: body.auto,
    userId: req.auth.userId,
    deviceId: req.auth.deviceId,
    ip: req.ip,
    idempotencyKey,
  });
  // Task 13: wire the previously-dead noticeAcceptedAt/noticeVersion fields on the
  // user doc (spec §6.8 gap) when a notice_accepted client event is ingested. This is
  // a SEPARATE, additive write to the users collection — `body.noticeVersion` is never
  // passed into audit.recordEvent above (it is not in audit.js's CORE_FIELDS list), so
  // it never enters the hashed audit core / hash chain. Best-effort and fully guarded:
  // a failure here must never undo or fail the already-durably-recorded audit event.
  if (body.eventType === 'notice_accepted') {
    try {
      const patch = { noticeAcceptedAt: ctx.clock.now(), updatedAt: ctx.clock.now() };
      if (body.noticeVersion != null) patch.noticeVersion = String(body.noticeVersion);
      await ctx.repo.users.updateById(req.auth.userId, patch);
    } catch {
      // best-effort only — never let this affect the audit response above
    }
  }
  return { status: 200, body: out };
}

async function hAdminVerifyAudit(ctx) {
  const out = await audit.verifyAuditChain(ctx);
  return { status: 200, body: out };
}

async function hAddIpRule(ctx, req) {
  const { scope, userId, type, cidr, reason } = req.body || {};
  const out = await access.addIpRule(ctx, { adminId: req.auth.userId, scope, userId, type, cidr, reason, currentIp: req.ip });
  return { status: 201, body: out };
}

async function hRemoveIpRule(ctx, req) {
  const { ruleId } = req.body || {};
  const out = await access.removeIpRule(ctx, { adminId: req.auth.userId, ruleId });
  return { status: 200, body: out };
}

async function hListIpRules(ctx, req) {
  const out = await access.listIpRules(ctx, { adminId: req.auth.userId, scope: req.query.scope, userId: req.query.userId });
  return { status: 200, body: { rules: out } };
}

async function hSetGeoFence(ctx, req) {
  const { targetUserId, countries } = req.body || {};
  const out = await access.setGeoFence(ctx, { adminId: req.auth.userId, targetUserId, countries });
  return { status: 200, body: out };
}

// F2: per-user country DENY-list — mutation route, deliberately carries NO
// `webView` flag (mirrors POST /admin/geo-fence above) so the view-only web
// console can never reach it.
async function hSetBlockedCountries(ctx, req) {
  const { targetUserId, countries } = req.body || {};
  const out = await access.setBlockedCountries(ctx, { adminId: req.auth.userId, targetUserId, countries });
  return { status: 200, body: out };
}

function scopedIdempotencyKey(req) {
  const raw = req.headers[IDEMPOTENCY_HEADER];
  return raw ? `${req.auth.userId}:${raw}` : undefined;
}

async function hExportAuthorize(ctx, req) {
  const out = await transfer.authorizeExport(ctx, {
    userId: req.auth.userId, deviceId: req.auth.deviceId, ip: req.ip,
    fileMeta: (req.body || {}).fileMeta, idempotencyKey: scopedIdempotencyKey(req),
  });
  return { status: 200, body: out };
}

async function hImportAuthorize(ctx, req) {
  const { watermarkId, fileMeta } = req.body || {};
  const out = await transfer.authorizeImport(ctx, {
    userId: req.auth.userId, deviceId: req.auth.deviceId, ip: req.ip,
    watermarkId, fileMeta, idempotencyKey: scopedIdempotencyKey(req),
  });
  return { status: 200, body: out };
}

async function hWatermarkTrace(ctx, req) {
  const out = await watermark.trace(ctx, req.query.watermarkId);
  return { status: 200, body: out };
}

async function hHeartbeat(ctx, req) {
  const b = req.body || {};
  const report = { ipv4: b.ipv4, ipv6: b.ipv6, geo4: b.geo4, geo6: b.geo6, appVersion: b.appVersion, os: b.os };
  // Ingest the client's telemetry (both public IPs + coarse geo) + cross-check.
  await presence.recordHeartbeat(ctx, { user: { _id: req.auth.userId }, deviceId: req.auth.deviceId, observedIp: req.ip, report });
  // One check-in also fetches pending commands (spec §7) — telemetry + poll in one round trip.
  const cmds = await commands.pollCommands(ctx, { userId: req.auth.userId, deviceId: req.auth.deviceId });
  // Live-read so the client learns of an admin-side monitoring toggle on the
  // very next heartbeat. Default true (managed tool, see users.js): only an
  // explicit `false` on the user record disables it. `!user ||` also covers
  // the (edge-case) missing record, so default-true holds even then.
  const user = await ctx.repo.users.findById(req.auth.userId);
  const monitoringEnabled = !user || user.monitoringEnabled !== false;
  return { status: 200, body: { ok: true, commands: cmds.commands, monitoringEnabled } };
}

async function hEnqueueCommand(ctx, req) {
  const { deviceId, type } = req.body || {};
  const out = await commands.enqueueCommand(ctx, { adminId: req.auth.userId, deviceId, type });
  return { status: 201, body: out };
}

async function hPollCommands(ctx, req) {
  const out = await commands.pollCommands(ctx, { userId: req.auth.userId, deviceId: req.auth.deviceId });
  return { status: 200, body: out };
}

async function hAckCommand(ctx, req) {
  const { commandId, result } = req.body || {};
  const out = await commands.ackCommand(ctx, { userId: req.auth.userId, deviceId: req.auth.deviceId, commandId, result });
  return { status: 200, body: out };
}

async function hSetMonitoring(ctx, req) {
  const { targetUserId, enabled } = req.body || {};
  const out = await entitlements.setEntitlement(ctx, { adminId: req.auth.userId, targetUserId, field: 'monitoringEnabled', value: !!enabled });
  return { status: 200, body: out };
}

// Per-user admin email notification gate (E3): mutation route, deliberately
// carries NO `webView` flag (mirrors hSetMonitoring/POST /admin/monitoring) —
// the web console stays strictly view-only.
async function hSetAlerts(ctx, req) {
  const { targetUserId, enabled } = req.body || {};
  const out = await entitlements.setEntitlement(ctx, { adminId: req.auth.userId, targetUserId, field: 'alertsEnabled', value: !!enabled });
  return { status: 200, body: out };
}

async function hReportTimeline(ctx, req) {
  const out = await reporting.activityTimeline(ctx, { adminId: req.auth.userId, userId: req.query.userId, days: req.query.days });
  return { status: 200, body: out };
}

async function hReportDevices(ctx, req) {
  const out = await reporting.deviceInventory(ctx, { adminId: req.auth.userId });
  return { status: 200, body: out };
}

async function hReportAlerts(ctx, req) {
  const out = await reporting.alertsFeed(ctx, { adminId: req.auth.userId, days: req.query.days });
  return { status: 200, body: out };
}

async function hReportStorage(ctx, req) {
  const out = await reporting.storagePercent(ctx, { adminId: req.auth.userId });
  return { status: 200, body: out };
}

async function hReportTransfers(ctx, req) {
  const out = await reporting.transferFlows(ctx, { adminId: req.auth.userId, days: req.query.days });
  return { status: 200, body: out };
}

async function hReportUsers(ctx, req) {
  const out = await reporting.usersDirectory(ctx, { adminId: req.auth.userId });
  return { status: 200, body: out };
}

// Usage tracking + reports (spec f1a-usage-backend, additive; NOT an audit
// event — see the CLIENT_EVENT_TYPES comment above; usage snapshots never
// touch audit.recordEvent / CORE_FIELDS / the hash chain).

// POST /usage/snapshot — member write, deliberately carries NO `webView` flag
// (the browser/web console never writes usage data). `userId` is ALWAYS
// req.auth.userId (the verified access token's subject) — never taken from
// the request body, so a client can never stamp another user's snapshot.
async function hUsageSnapshot(ctx, req) {
  const { accounts } = req.body || {};
  const out = await usagestore.recordUsageSnapshot(ctx, { userId: req.auth.userId, accounts });
  return { status: 200, body: out };
}

// GET /usage/me — self-scoped read (desktop only; NO webView — the web
// console has no per-device "my usage" concept). `userId` is req.auth.userId,
// never a query filter, so a caller can only ever read their own docs.
async function hUsageMe(ctx, req) {
  const out = await usagestore.myUsage(ctx, { userId: req.auth.userId, days: req.query.days });
  return { status: 200, body: out };
}

// GET /admin/reports/usage — admin fleet overview (who/which account/how
// much/when), read-only, allowlisted for the view-scope web console.
async function hAdminUsageOverview(ctx, req) {
  const out = await reporting.usageOverview(ctx, { adminId: req.auth.userId, days: req.query.days });
  return { status: 200, body: out };
}

async function hAuditExport(ctx, req) {
  const out = await audit.exportSigned(ctx, { from: req.query.from, to: req.query.to });
  return { status: 200, body: out };
}

async function hVerifyPermChain(ctx) {
  const out = await entitlements.verifyPermissionChain(ctx);
  return { status: 200, body: out };
}

// Task 8: per-PC encrypted Claude-cred copy (admin-only, server-key-encrypted
// at rest). deviceId is ALWAYS taken from the verified access token's `did`
// claim, never the request body — a client cannot upload a blob under a
// deviceId it doesn't hold a token for.
function isPlainPayloadObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

async function hPutDeviceClaudeCred(ctx, req) {
  const payload = (req.body || {}).payload;
  if (!isPlainPayloadObject(payload)) throw httpError(400, 'payload must be an object.');
  const out = await devicecreds.storeClaudeCred(ctx, {
    deviceId: req.auth.deviceId, userId: req.auth.userId, payload,
  });
  return { status: 200, body: out };
}

async function hAdminGetDeviceClaudeCred(ctx, req) {
  const deviceId = req.query.deviceId;
  if (!deviceId) throw httpError(400, 'Missing device id.');
  const out = await devicecreds.readClaudeCred(ctx, { deviceId });
  return { status: 200, body: out };
}

// route key → { handler, auth, admin }
const ROUTES = {
  'GET /health': { handler: hHealth },
  'POST /auth/signup': { handler: hSignup },
  'POST /auth/verify-email': { handler: hVerifyEmail },
  'POST /auth/login': { handler: hLogin },
  'POST /auth/web-login': { handler: hWebLogin },
  'POST /auth/refresh': { handler: hRefresh },
  'POST /auth/logout': { handler: hLogout },
  'POST /auth/change-password': { handler: hChangePassword, auth: true, admin: true },
  'GET /entitlements/me': { handler: hEntitlementsMe, auth: true },
  'POST /audit/events': { handler: hAuditEvents, auth: true },
  'POST /admin/entitlements': { handler: hAdminSetEntitlement, auth: true, admin: true },
  'POST /admin/users': { handler: hAdminCreateUser, auth: true, admin: true },
  'POST /admin/users/approve': { handler: hApproveUser, auth: true, admin: true },
  'POST /admin/users/reject': { handler: hRejectUser, auth: true, admin: true },
  'GET /admin/audit/verify': { handler: hAdminVerifyAudit, auth: true, admin: true, webView: true },
  'POST /admin/ip-rules': { handler: hAddIpRule, auth: true, admin: true },
  'POST /admin/ip-rules/remove': { handler: hRemoveIpRule, auth: true, admin: true },
  'GET /admin/ip-rules': { handler: hListIpRules, auth: true, admin: true, webView: true },
  'POST /admin/geo-fence': { handler: hSetGeoFence, auth: true, admin: true },
  'POST /admin/blocked-countries': { handler: hSetBlockedCountries, auth: true, admin: true },
  'POST /export/authorize': { handler: hExportAuthorize, auth: true },
  'POST /import/authorize': { handler: hImportAuthorize, auth: true },
  'GET /watermarks/trace': { handler: hWatermarkTrace, auth: true, admin: true, webView: true },
  'POST /heartbeat': { handler: hHeartbeat, auth: true },
  'POST /admin/commands': { handler: hEnqueueCommand, auth: true, admin: true },
  'POST /commands/poll': { handler: hPollCommands, auth: true },
  'POST /commands/ack': { handler: hAckCommand, auth: true },
  'POST /admin/monitoring': { handler: hSetMonitoring, auth: true, admin: true },
  'POST /admin/alerts-enabled': { handler: hSetAlerts, auth: true, admin: true },
  'GET /admin/reports/timeline': { handler: hReportTimeline, auth: true, admin: true, webView: true },
  'GET /admin/reports/devices': { handler: hReportDevices, auth: true, admin: true, webView: true },
  'GET /admin/reports/alerts': { handler: hReportAlerts, auth: true, admin: true, webView: true },
  'GET /admin/reports/storage': { handler: hReportStorage, auth: true, admin: true, webView: true },
  'GET /admin/reports/transfers': { handler: hReportTransfers, auth: true, admin: true, webView: true },
  'GET /admin/reports/users': { handler: hReportUsers, auth: true, admin: true, webView: true },
  'POST /usage/snapshot': { handler: hUsageSnapshot, auth: true },
  'GET /usage/me': { handler: hUsageMe, auth: true },
  'GET /admin/reports/usage': { handler: hAdminUsageOverview, auth: true, admin: true, webView: true },
  'GET /admin/audit/export': { handler: hAuditExport, auth: true, admin: true, webView: true },
  'GET /admin/permission-changes/verify': { handler: hVerifyPermChain, auth: true, admin: true, webView: true },
  'POST /devices/claude-cred': { handler: hPutDeviceClaudeCred, auth: true },
  // webDeny: a decrypted Claude-credential read must NEVER reach a browser
  // (web-console) session — those secrets are the whole reason for the at-rest
  // field encryption, so the browser attack surface must not see them. The
  // web-login token is scope:'web' (full admin otherwise); this flag makes the
  // handleRequest gate refuse it here. Desktop/CLI (no scope) still reach it.
  'GET /admin/devices/claude-cred': { handler: hAdminGetDeviceClaudeCred, auth: true, admin: true, webDeny: true },
};

function matchRoute(method, path) {
  return ROUTES[`${method} ${path}`] || null;
}

// Best-effort geo lookup for the request pipeline (geo-fence + reporting).
// Never throws — geo is advisory for access decisions (fence fails closed on a
// null result, handled in access.js).
async function resolveGeo(ctx, ip) {
  try {
    return ctx.geo && typeof ctx.geo.lookup === 'function' ? await ctx.geo.lookup(ip) : null;
  } catch {
    return null;
  }
}

// Extract + verify the Bearer access token. Throws 401 on any problem.
function requireBearer(ctx, headers) {
  const raw = String(headers.authorization || '');
  const m = /^Bearer\s+(.+)$/i.exec(raw);
  if (!m) throw httpError(401, 'Authentication required.');
  const payload = tokens.verifyAccessToken(ctx, m[1]); // throws 401 if invalid/expired
  return { userId: payload.sub, role: payload.role, deviceId: payload.did, scope: payload.scope };
}

// Map any thrown error to a safe response. 5xx → generic body + server log;
// 4xx (curated, exposable) → its own message. Never leaks tokens/PII/stack.
function toErrorResponse(ctx, err, req) {
  const status = err && err.status ? err.status : 500;
  if (status >= 500) {
    if (ctx.logger && ctx.logger.error) {
      ctx.logger.error(redactSensitive(`${req.method} ${req.path} -> ${err && err.message}`));
    }
    return { status: 500, body: { error: 'Something went wrong. Please try again.' }, headers: {} };
  }
  return { status, body: { error: err && err.expose ? err.message : 'Request failed.' }, headers: {} };
}

async function handleRequest(ctx, req) {
  try {
    const blocked = requestBlockReason(req.method, req.headers, ctx.config.allowedHosts);
    if (blocked) return { status: 403, body: { error: blocked }, headers: {} };

    const route = matchRoute(req.method, req.path);
    if (!route) return { status: 404, body: { error: 'Not found.' }, headers: {} };

    // Global IP allow/block gate — runs on EVERY matched route, including the
    // unauthenticated ones (login/signup/refresh), so a globally-blocklisted
    // range is refused before it can brute-force credentials (spec §6.5).
    await access.enforceGlobalIp(ctx, req.ip);

    let auth = null;
    if (route.auth) {
      auth = requireBearer(ctx, req.headers);
      // Scope-based default-deny, checked right after the token verifies (before
      // the live admin-role check or the handler runs — so a disallowed route
      // never executes and spends no DB round trip; unauthenticated/unmatched
      // 401/404 behavior is untouched). Absence of `scope` = full privilege
      // (desktop/CLI/normal login); a scope can only ever REDUCE what a token may
      // do. Two scopes exist:
      //   'view' — the dormant read-only web scope: reaches ONLY route.webView
      //            reads (kept for a possible future read-only viewer role).
      //   'web'  — the current /auth/web-login (full-admin) console: full admin
      //            EXCEPT routes flagged route.webDeny (a browser session must
      //            never reach those — e.g. the decrypted Claude-credential read,
      //            whose secrets must never leave for a browser attack surface).
      if (auth.scope === 'view' && !route.webView) {
        return { status: 403, body: { error: 'This session is view-only.' }, headers: {} };
      }
      if (auth.scope === 'web' && route.webDeny) {
        return { status: 403, body: { error: 'This action is not available in the web console.' }, headers: {} };
      }
      const user = await ctx.repo.users.findById(auth.userId);
      if (route.admin && (!user || user.role !== 'admin' || user.status !== 'active')) {
        return { status: 403, body: { error: 'Admin privileges required.' }, headers: {} };
      }
      // Per-user IP rules + geo-fence gate — post-auth (identity now known).
      if (user) {
        // GEO-1: the resolved geo is used ONLY by enforceGeoFence/enforceCountryBlock,
        // both of which early-return for a user with neither an active allow-fence
        // NOR an active country deny-list — so resolving it unconditionally for
        // every authenticated request wastes an external provider call (e.g.
        // GEO_PROVIDER=ip-api's ~45 req/min free-tier cap) for every unrestricted
        // user, and once that cap is exhausted, RESTRICTED users start failing
        // closed (403) because their genuine lookups fail too. Confine the lookup
        // to users who actually carry an active fence OR block-list (F2 widens this
        // from fence-only); enforceUserIp (the per-user IP allow/block rules) still
        // runs for everyone regardless.
        const hasFence = user.geoFence && Array.isArray(user.geoFence.countries) && user.geoFence.countries.length > 0;
        const hasBlock = user.blockedCountries && Array.isArray(user.blockedCountries.countries) && user.blockedCountries.countries.length > 0;
        const needGeo = hasFence || hasBlock;
        const geo = needGeo ? await resolveGeo(ctx, req.ip) : null;
        await access.enforceUserIp(ctx, user, req.ip, geo);
      }
    }

    const result = await route.handler(ctx, { ...req, auth });
    return { status: result.status || 200, body: result.body, headers: result.headers || {} };
  } catch (err) {
    return toErrorResponse(ctx, err, req);
  }
}

module.exports = { handleRequest, matchRoute, toErrorResponse, ROUTES, APP_NAME, VERSION };
