'use strict';
// Admin provisioning used by the seed CLI. createAdmin makes a fully active,
// email-verified admin with import/export enabled (an admin manages the tool,
// so it is entitled by default). Reuses createUser so email normalization,
// blind indexing, encryption, and duplicate detection all apply.

const { createUser, findUserByEmail } = require('./users');
const { requireAdmin, setEntitlement } = require('./entitlements');
const { httpError } = require('./errors');

async function hasAdmin(ctx) {
  const admins = await ctx.repo.users.find({ role: 'admin' });
  return admins.length > 0;
}

async function createAdmin(ctx, { email, password }) {
  const user = await createUser(ctx, { email, password, role: 'admin' });
  const now = ctx.clock.now();
  await ctx.repo.users.updateById(user._id, {
    status: 'active',
    emailVerified: true,
    importEnabled: true,
    exportEnabled: true,
    updatedAt: now,
  });
  return { userId: user._id, role: 'admin' };
}

// Admin-side "add employee" (distinct from createAdmin above, which is the
// seed-CLI's own bootstrap path). An admin directly provisions a member (or
// another admin) who is ACTIVE + email-verified immediately — no OTP, since
// this is an admin-vouched account, not an anonymous self-signup. Reuses
// createUser for email/password validation, blind indexing, and encryption.
//
// Any NON-default initial grant (import/export/status) is applied through the
// AUDITED setEntitlement path — unlike the base activation above, which is not
// itself a mutation of existing authority (a brand-new record has none yet) —
// so every authority change an admin hands out at creation time still lands in
// the tamper-evident permission_changes ledger.
async function createManagedUser(ctx, { adminId, email, password, role, importEnabled, exportEnabled, status }) {
  await requireAdmin(ctx, adminId); // defense-in-depth; the route already gates this too

  const role2 = role === 'admin' ? 'admin' : 'member';
  const user = await createUser(ctx, { email, password, role: role2 });
  const now = ctx.clock.now();
  await ctx.repo.users.updateById(user._id, {
    status: 'active',
    emailVerified: true,
    // F3 provenance: WHO created this user. A plain doc field (not a
    // permission_changes ledger entry) — see the module header comment: a
    // brand-new record has no prior authority to mutate, so the base create
    // stays un-ledgered exactly as before; this is purely additive.
    createdBy: adminId,
    updatedAt: now,
  });

  if (importEnabled) {
    await setEntitlement(ctx, { adminId, targetUserId: user._id, field: 'importEnabled', value: true });
  }
  if (exportEnabled) {
    await setEntitlement(ctx, { adminId, targetUserId: user._id, field: 'exportEnabled', value: true });
  }
  if (status && status !== 'active') {
    await setEntitlement(ctx, { adminId, targetUserId: user._id, field: 'status', value: status });
  }

  return {
    userId: user._id,
    role: role2,
    status: status || 'active',
    importEnabled: !!importEnabled,
    exportEnabled: !!exportEnabled,
    createdBy: adminId,
  };
}

// Admin APPROVES a pending self-signup (the OTP-free flow): status -> active
// through the AUDITED setEntitlement path (lands in the permission_changes
// ledger), plus emailVerified -> true (a plain field — admin approval vouches
// for the email in this managed product, exactly as createManagedUser does).
// Idempotent-ish: approving an already-active user just re-activates it.
async function approveUser(ctx, { adminId, targetUserId }) {
  await requireAdmin(ctx, adminId);
  const user = await ctx.repo.users.findById(targetUserId);
  if (!user) throw httpError(404, 'User not found.');
  await setEntitlement(ctx, { adminId, targetUserId, field: 'status', value: 'active' });
  await ctx.repo.users.updateById(targetUserId, { emailVerified: true, updatedAt: ctx.clock.now() });
  return { userId: targetUserId, status: 'active', emailVerified: true };
}

// Admin REJECTS a pending signup: status -> rejected through the audited path.
// The account is kept for the record and can never sign in (login refuses
// 'rejected'); an admin can still re-approve or deprovision it later.
async function rejectUser(ctx, { adminId, targetUserId }) {
  await requireAdmin(ctx, adminId);
  const user = await ctx.repo.users.findById(targetUserId);
  if (!user) throw httpError(404, 'User not found.');
  await setEntitlement(ctx, { adminId, targetUserId, field: 'status', value: 'rejected' });
  return { userId: targetUserId, status: 'rejected' };
}

// Dev-only convenience for a REPO=memory live demo (Phase 5 Task 3): ensure
// an active, email-verified admin exists using the SEED_ADMIN_EMAIL /
// SEED_ADMIN_PASSWORD config values. No-op (returns null) when either is
// unset. Idempotent: if a user with that email already exists this leaves it
// untouched (never overwrites a password/role on an existing account) rather
// than erroring on the createUser() duplicate-email check.
//
// Callers gate this to the memory-repo branch only (see context.js) — it is
// never invoked on the production/Mongo path, seed vars or not.
async function ensureSeedAdmin(ctx) {
  const email = ctx.config.seedAdminEmail;
  const password = ctx.config.seedAdminPassword;
  if (!email || !password) return null;
  const existing = await findUserByEmail(ctx, email);
  if (existing) return { userId: existing._id, role: existing.role, seeded: false };
  const res = await createAdmin(ctx, { email, password });
  return { ...res, seeded: true };
}

module.exports = { hasAdmin, createAdmin, createManagedUser, approveUser, rejectUser, ensureSeedAdmin };
