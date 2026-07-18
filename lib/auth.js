'use strict';
// Login / refresh / logout.
//
// Login: scrypt verify → issue Ed25519 access token + rotating opaque refresh
// token (device-bound). Failed logins count toward a lockout; a correct
// password while locked is still refused.
//
// Refresh: rotates the refresh token. A previously-rotated (revoked) token being
// replayed is treated as THEFT — the entire token family is revoked
// (reuse-detection). Refresh is bound to the deviceId; a mismatch also kills the
// family. Rotated sessions are retained (revoked) until natural expiry so reuse
// can always be detected.

const crypto = require('crypto');
const { verifyPassword, hashPassword } = require('./passwords');
const { findUserByEmail, MIN_PASSWORD_LEN } = require('./users');
const tokens = require('./tokens');
const anomaly = require('./anomaly');
const presence = require('./presence');
const entitlements = require('./entitlements');
const audit = require('./audit');
const { httpError } = require('./errors');

// A fixed dummy hash used to equalize response timing when an email is unknown,
// so attackers cannot distinguish "no such user" from "wrong password" by timing.
let DUMMY_HASH = null;
function dummyHash(ctx) {
  if (!DUMMY_HASH) DUMMY_HASH = hashPassword('timing-normalization-placeholder', ctx.config.scrypt);
  return DUMMY_HASH;
}

async function registerFailedLogin(ctx, user, now) {
  const { maxFails, windowMs, cooldownMs } = ctx.config.loginLockout;
  const lastAt = user.lastFailedAt ? new Date(user.lastFailedAt).getTime() : 0;
  const withinWindow = lastAt && (now.getTime() - lastAt) <= windowMs;
  const fails = (withinWindow ? (user.failedLogins || 0) : 0) + 1;
  const patch = { failedLogins: fails, lastFailedAt: now, updatedAt: now };
  if (fails >= maxFails) {
    patch.lockedUntil = new Date(now.getTime() + cooldownMs);
    patch.failedLogins = 0; // fresh budget after the cooldown
  }
  await ctx.repo.users.updateById(user._id, patch);
}

async function issueSession(ctx, user, deviceId, scope) {
  const now = ctx.clock.now();
  const familyId = crypto.randomUUID();
  const refreshToken = tokens.generateRefreshToken();
  const doc = {
    userId: user._id,
    familyId,
    deviceId,
    tokenHash: tokens.hashRefreshToken(refreshToken),
    issuedAt: now,
    // Stamped once at login and copied verbatim through every rotation, so the
    // absolute-lifetime cap (#11) applies to the whole family, not per-rotation.
    familyStartedAt: now,
    expiresAt: new Date(now.getTime() + ctx.config.refreshTokenTtlMs),
    revokedAt: null,
  };
  // Scope is persisted on the session/refresh-token family itself (never just
  // baked into the access token) so `refresh` can always re-mint from the
  // stored value rather than trusting whatever a client claims. Omitted
  // entirely for ordinary (full-privilege) sessions — backward compatible with
  // every session row that predates this field.
  if (scope) doc.scope = scope;
  await ctx.repo.sessions.insert(doc);
  return buildTokenResponse(ctx, user, deviceId, refreshToken, now, scope);
}

function buildTokenResponse(ctx, user, deviceId, refreshToken, now, scope) {
  const accessToken = tokens.signAccessToken(ctx, { userId: user._id, role: user.role, deviceId, scope });
  const out = {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    accessExpiresAt: new Date(now.getTime() + ctx.config.accessTokenTtlMs),
    refreshExpiresAt: new Date(now.getTime() + ctx.config.refreshTokenTtlMs),
    role: user.role,
  };
  // Additive only: ordinary login/refresh callers never pass `scope`, so their
  // response shape is byte-for-byte unchanged.
  if (scope) out.scope = scope;
  return out;
}

// Shared credential-verification core against an ALREADY-RESOLVED user doc:
// locked account and wrong password both take the identical timing-normalized
// path to the identical generic 401. Factored out of verifyCredentials so a
// caller that already holds the user (e.g. change-password, re-authenticating
// the CURRENTLY authenticated principal by userId, not email) can reuse the
// exact same lockout bookkeeping + timing normalization without a redundant
// email lookup.
async function verifyAgainstUser(ctx, user, password, ip, now) {
  const generic = () => httpError(401, 'Incorrect email or password.');

  // Locked accounts return the SAME generic 401 as a wrong password / unknown
  // email, so lockout is not an account-existence oracle. (We still refuse the
  // attempt without verifying the password.)
  if (user.lockedUntil && new Date(user.lockedUntil) > now) {
    // Burn a comparable scrypt cost before refusing, so the locked branch is not
    // a fast-path timing oracle for "this account exists and is locked" (#17/#19).
    verifyPassword(password, dummyHash(ctx));
    await anomaly.recordLoginFailure(ctx, ip);
    throw generic();
  }
  if (!verifyPassword(password, user.passwordHash)) {
    await registerFailedLogin(ctx, user, now);
    await anomaly.recordLoginFailure(ctx, ip);
    throw generic();
  }
  return user;
}

// Shared credential-verification core for both /auth/login and /auth/web-login:
// unknown email, locked account, and wrong password all take the identical
// timing-normalized path to the identical generic 401 — a caller-specific
// authorization check (active/admin/etc.) happens AFTER this returns.
async function verifyCredentials(ctx, { email, password, ip }, now) {
  const user = await findUserByEmail(ctx, email);
  if (!user) {
    verifyPassword(password, dummyHash(ctx)); // burn comparable time
    await anomaly.recordLoginFailure(ctx, ip);
    throw httpError(401, 'Incorrect email or password.');
  }
  return verifyAgainstUser(ctx, user, password, ip, now);
}

async function login(ctx, { email, password, deviceId, ip, scope }) {
  if (!deviceId) throw httpError(400, 'Missing device id.');
  const now = ctx.clock.now();
  const user = await verifyCredentials(ctx, { email, password, ip }, now);
  if (user.status !== 'active') {
    if (user.status === 'pending') throw httpError(403, 'Your account is waiting for admin approval.');
    if (user.status === 'rejected') throw httpError(403, 'Your account request was declined by an administrator.');
    throw httpError(403, 'This account is not permitted to sign in.');
  }
  await ctx.repo.users.updateById(user._id, {
    failedLogins: 0, lockedUntil: null, lastLoginAt: now, updatedAt: now,
  });
  // Device presence + new-device/impossible-travel evaluation (never throws).
  await presence.recordPresence(ctx, { user, deviceId, ip });
  return issueSession(ctx, user, deviceId, scope);
}

// Admin-only login for the web console (Phase 5 Addendum B#6). Credentials are
// verified through the identical path as `login` (same generic 401, same
// lockout bookkeeping, same timing normalization). Only AFTER credentials
// verify do we apply the admin+active gate — refusing with the same uniform
// 403 whether the account is a non-admin or simply not active, so this
// endpoint never leaks which condition failed. No session or token is created
// on refusal. On success mints a scope:'web' admin session: the product owner
// chose a FULL-admin web console (approve/reject + manage users from the
// browser), and only admins can reach this endpoint — so 'web' is full admin
// EXCEPT routes flagged route.webDeny (the decrypted Claude-credential read),
// which a browser session must never reach. 'web' is stored on the session
// family so refresh re-mints it (never client-supplied). The 'view'-scope
// machinery + route.webView flags remain but are now unused by this path.
async function webLogin(ctx, { email, password, deviceId, ip }) {
  if (!deviceId) throw httpError(400, 'Missing device id.');
  const now = ctx.clock.now();
  const user = await verifyCredentials(ctx, { email, password, ip }, now);
  if (user.role !== 'admin' || user.status !== 'active') {
    throw httpError(403, 'Admin privileges required.');
  }
  await ctx.repo.users.updateById(user._id, {
    failedLogins: 0, lockedUntil: null, lastLoginAt: now, updatedAt: now,
  });
  await presence.recordPresence(ctx, { user, deviceId, ip });
  return issueSession(ctx, user, deviceId, 'web');
}

async function revokeFamily(ctx, familyId, now, reason) {
  const members = await ctx.repo.sessions.find({ familyId, revokedAt: null });
  for (const m of members) await ctx.repo.sessions.updateById(m._id, { revokedAt: now, revokeReason: reason });
}

// Revoke EVERY live session for a user across all families (a user may be logged
// in on several devices). Used by unilateral admin actions — deprovision /
// disable / force-logout — so revocation is complete, not one-family-scoped.
async function revokeAllForUser(ctx, userId, now, reason) {
  const members = await ctx.repo.sessions.find({ userId, revokedAt: null });
  for (const m of members) await ctx.repo.sessions.updateById(m._id, { revokedAt: now, revokeReason: reason });
}

// Revoke every live session for a user EXCEPT the ones bound to
// `exceptDeviceId`. Used by password change (Phase 5 Addendum B#7) so the
// device that just re-authenticated with the current password is not logged
// out of its own session, while every OTHER device's session is cut off.
async function revokeAllForUserExceptDevice(ctx, userId, exceptDeviceId, now, reason) {
  const members = await ctx.repo.sessions.find({ userId, revokedAt: null, deviceId: { $ne: exceptDeviceId } });
  for (const m of members) await ctx.repo.sessions.updateById(m._id, { revokedAt: now, revokeReason: reason });
}

// Admin self-service password change (Phase 5 Addendum B#7). Re-auth: the
// caller must present their CURRENT password, verified through the identical
// timing-normalized path as /auth/login (same generic 401, same lockout
// bookkeeping via verifyAgainstUser) — so this endpoint can never be used as a
// password-guessing oracle. On success: the password hash is rotated; every
// OTHER device's refresh-token family is revoked (the calling device's own
// session survives, since it just proved the current password); the change is
// recorded twice — a permission_changes ledger entry (never any password
// material — field/from/to are structural only) and a server-authored
// audit_events row (idempotency-keyed so a retried request doesn't duplicate).
async function changePassword(ctx, { userId, deviceId, currentPassword, newPassword, ip, idempotencyKey }) {
  const now = ctx.clock.now();
  const user = await ctx.repo.users.findById(userId);
  if (!user) throw httpError(401, 'Incorrect email or password.');

  await verifyAgainstUser(ctx, user, currentPassword, ip, now);

  if (!newPassword || String(newPassword).length < MIN_PASSWORD_LEN) {
    throw httpError(400, `Password must be at least ${MIN_PASSWORD_LEN} characters.`);
  }

  const newHash = hashPassword(newPassword, ctx.config.scrypt);
  await ctx.repo.users.updateById(userId, {
    passwordHash: newHash, failedLogins: 0, lockedUntil: null, updatedAt: now,
  });

  await revokeAllForUserExceptDevice(ctx, userId, deviceId, now, 'password_changed');

  await entitlements.appendPermissionChange(ctx, {
    adminId: userId, targetUserId: userId, field: 'password_changed', from: null, to: null,
  });
  await audit.recordEvent(ctx, {
    eventType: 'password_changed', userId, deviceId, idempotencyKey,
  });

  return { ok: true };
}

async function refresh(ctx, { refreshToken, deviceId, ip }) {
  if (!deviceId) throw httpError(400, 'Missing device id.');
  const now = ctx.clock.now();
  const invalid = () => httpError(401, 'Invalid session. Please sign in again.');
  const expired = () => httpError(401, 'Session expired. Please sign in again.');

  const retry = () => httpError(409, 'Refresh already in progress. Please retry.');

  const tokenHash = tokens.hashRefreshToken(String(refreshToken || ''));
  const session = await ctx.repo.sessions.findOne({ tokenHash });
  if (!session) throw invalid();

  // ABSOLUTE-LIFETIME CAP (#11): a refresh family may not outlive this cap no
  // matter how often it rotates. Checked BEFORE the benign-retry/grace branch so
  // a past-cap family is hard-revoked even when a double-submit is in flight
  // (never a soft 409). familyStartedAt is copied through every rotation; legacy
  // sessions without it fall back to issuedAt.
  const familyStart = new Date(session.familyStartedAt || session.issuedAt).getTime();
  if (now.getTime() - familyStart > ctx.config.refreshAbsoluteLifetimeMs) {
    await revokeFamily(ctx, session.familyId, now, 'absolute_lifetime');
    throw expired();
  }

  // A revoked token presented again is EITHER a benign double-submit (a network
  // retry of the just-rotated token) OR theft (an old leaked token). Distinguish
  // by time + replacement liveness: within the grace window, with the immediate
  // replacement still live → benign retry (do NOT kill the family). Otherwise →
  // reuse-detection → revoke the whole family.
  if (session.revokedAt) {
    const withinGrace = (now.getTime() - new Date(session.revokedAt).getTime()) <= ctx.config.refreshGraceMs;
    const child = session.replacedByHash
      ? await ctx.repo.sessions.findOne({ tokenHash: session.replacedByHash })
      : null;
    const childLive = child && !child.revokedAt && new Date(child.expiresAt) > now;
    if (withinGrace && childLive) throw retry();
    await revokeFamily(ctx, session.familyId, now, 'reuse_detected');
    throw expired();
  }
  if (new Date(session.expiresAt) <= now) throw expired();
  if (session.deviceId !== deviceId) {
    await revokeFamily(ctx, session.familyId, now, 'device_mismatch');
    throw invalid();
  }

  const user = await ctx.repo.users.findById(session.userId);
  if (!user || user.status !== 'active') {
    await revokeFamily(ctx, session.familyId, now, 'user_inactive');
    throw invalid();
  }

  // Rotate with an ATOMIC compare-and-swap: only the writer that flips
  // revokedAt null→now proceeds to mint the child. A concurrent second refresh
  // fails the CAS (revokedAt already set) and returns a benign retry — so two
  // racing refreshes can never mint two live sibling tokens (no TOCTOU fork).
  const newRefresh = tokens.generateRefreshToken();
  const newHash = tokens.hashRefreshToken(newRefresh);
  const won = await ctx.repo.sessions.updateOne(
    { _id: session._id, revokedAt: null },
    { $set: { revokedAt: now, replacedByHash: newHash } },
  );
  if (!won) throw retry();
  const childDoc = {
    userId: user._id,
    familyId: session.familyId,
    deviceId,
    tokenHash: newHash,
    issuedAt: now,
    familyStartedAt: session.familyStartedAt || session.issuedAt, // carry the family start through rotation
    expiresAt: new Date(now.getTime() + ctx.config.refreshTokenTtlMs),
    revokedAt: null,
  };
  // Scope is carried through rotation from the STORED session, never from the
  // request — a client cannot upgrade a view-only session by passing its own
  // `scope` on /auth/refresh (the body field, if present, is simply not read).
  if (session.scope) childDoc.scope = session.scope;
  await ctx.repo.sessions.insert(childDoc);
  // Device check-in on every rotation keeps lastSeen fresh (dead-man input).
  await presence.recordPresence(ctx, { user, deviceId, ip });
  return buildTokenResponse(ctx, user, deviceId, newRefresh, now, session.scope);
}

async function logout(ctx, { refreshToken }) {
  const tokenHash = tokens.hashRefreshToken(String(refreshToken || ''));
  const session = await ctx.repo.sessions.findOne({ tokenHash });
  if (session) await revokeFamily(ctx, session.familyId, ctx.clock.now(), 'logout');
  return { ok: true };
}

module.exports = {
  login, webLogin, refresh, logout, revokeFamily, revokeAllForUser,
  revokeAllForUserExceptDevice, changePassword,
};
