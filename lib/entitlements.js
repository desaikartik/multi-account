'use strict';
// Entitlements — the server-side enforcement point.
//
// Flags are read LIVE from `users` on every gated call and are NEVER trusted
// from the JWT, so an admin revoke takes effect on the very next request even
// if the client still holds a valid access token (CWE-602 mitigation).
//
// Admin-only mutations are recorded in the hash-chained permission_changes
// ledger (same tamper-evidence as the audit ledger).

const { httpError } = require('./errors');
const hashchain = require('./hashchain');

const PERM_DOMAIN = 'permission_changes';

// Fields an admin may mutate through this path.
const MUTABLE_FIELDS = new Set(['importEnabled', 'exportEnabled', 'entitlementExpiresAt', 'status', 'monitoringEnabled', 'alertsEnabled']);
const VALID_STATUSES = new Set(['active', 'pending', 'suspended', 'deprovisioned', 'rejected']);

function serializeVal(v) {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.toISOString();
  if (v === undefined) return null;
  return v;
}

// Read the effective entitlements for a user straight from the DB.
async function getLiveEntitlements(ctx, userId) {
  const user = await ctx.repo.users.findById(userId);
  if (!user) throw httpError(404, 'User not found.');
  const now = ctx.clock.now();
  const active = user.status === 'active';
  // Fail CLOSED: an unparseable stored expiry counts as expired, never permanent.
  const exp = user.entitlementExpiresAt ? new Date(user.entitlementExpiresAt) : null;
  const expired = !!exp && (Number.isNaN(exp.getTime()) || exp <= now);
  const live = active && !expired;
  return {
    status: user.status,
    importEnabled: !!user.importEnabled && live,
    exportEnabled: !!user.exportEnabled && live,
    entitlementExpiresAt: user.entitlementExpiresAt || null,
    expired,
  };
}

// Throw 403 unless the user may perform `action` ('import' | 'export') right now.
async function assertCan(ctx, userId, action) {
  const ent = await getLiveEntitlements(ctx, userId);
  if (ent.status !== 'active') throw httpError(403, 'Your account is not active.');
  const allowed = action === 'import' ? ent.importEnabled : ent.exportEnabled;
  if (!allowed) throw httpError(403, `You are not permitted to ${action}.`);
  return ent;
}

async function requireAdmin(ctx, adminId) {
  const admin = await ctx.repo.users.findById(adminId);
  if (!admin || admin.role !== 'admin' || admin.status !== 'active') {
    throw httpError(403, 'Admin privileges required.');
  }
  return admin;
}

// Append one admin action to the tamper-evident permission_changes ledger.
// Shared by entitlement mutation, ip-rule CRUD, geo-fence, monitoring toggle,
// and remote-command status changes — so EVERY admin authority change is chained
// (domain-separated from audit_events).
async function appendPermissionChange(ctx, { adminId, targetUserId, field, from, to }) {
  return hashchain.appendChained(ctx, ctx.repo.permissionChanges, ctx.config.auditHmacKey, {
    adminId,
    targetUserId: targetUserId == null ? null : targetUserId,
    field,
    from: serializeVal(from),
    to: serializeVal(to),
    serverTs: ctx.clock.now(),
  }, { domain: PERM_DOMAIN });
}

// Admin-only flag mutation → records in the ledger, then applies.
async function setEntitlement(ctx, { adminId, targetUserId, field, value }) {
  await requireAdmin(ctx, adminId);
  if (!MUTABLE_FIELDS.has(field)) throw httpError(400, 'That field cannot be changed here.');
  const target = await ctx.repo.users.findById(targetUserId);
  if (!target) throw httpError(404, 'User not found.');

  // Validate + coerce BEFORE any write, so a bad value can never (a) be silently
  // persisted (fail-open) nor (b) throw between the ledger append and the update.
  let to;
  if (field === 'importEnabled' || field === 'exportEnabled' || field === 'monitoringEnabled' || field === 'alertsEnabled') {
    to = !!value;
  } else if (field === 'entitlementExpiresAt') {
    if (value == null || value === '') {
      to = null;
    } else {
      const d = new Date(value);
      if (Number.isNaN(d.getTime())) throw httpError(400, 'Invalid expiry date.');
      to = d;
    }
  } else if (field === 'status') {
    if (!VALID_STATUSES.has(value)) throw httpError(400, 'Invalid status.');
    to = value;
  }

  const from = target[field] ?? null;
  const now = ctx.clock.now();

  // Record in the tamper-evident ledger FIRST, then apply — so an applied change
  // is never left unrecorded (over-record rather than silently under-record).
  await appendPermissionChange(ctx, { adminId, targetUserId, field, from, to });
  await ctx.repo.users.updateById(targetUserId, { [field]: to, updatedAt: now });

  return { field, from: serializeVal(from), to: serializeVal(to) };
}

// Verify the permission_changes chain (tamper check for the admin console).
// Uses the ledger's OWN anchors so tail-truncation is caught (gap #3), not only
// domain-separated HMAC. Falls back cleanly to a plain chain walk when no perm
// anchors exist yet (verifyEvents with an empty anchor set).
async function verifyPermissionChain(ctx) {
  const audit = require('./audit'); // lazy require to avoid a load-order cycle
  const entries = await ctx.repo.permissionChanges.find({});
  const anchors = await ctx.repo.permAnchors.find({});
  return audit.verifyEvents(entries, anchors, {
    hmacKey: ctx.config.auditHmacKey,
    anchorPublicKey: ctx.config.anchorPublicKey,
    domain: PERM_DOMAIN,
  });
}

module.exports = {
  getLiveEntitlements, assertCan, requireAdmin, setEntitlement, verifyPermissionChain,
  appendPermissionChange, serializeVal, PERM_DOMAIN, MUTABLE_FIELDS,
};
