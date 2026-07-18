'use strict';
// IP allow/block + geo-fence enforcement (spec §6.5).
//
// Pipeline placement (see routes.js):
//   - enforceGlobalIp runs PRE-AUTH on every request (userId unknown), so a
//     globally-blocklisted range is refused even on login/signup/refresh.
//   - enforceUserIp runs POST-AUTH (per-user rules + geo-fence).
// Both must pass, so global + per-user allow-lists compose as an INTERSECTION.
//
// Precedence within a scope: a BLOCK match wins; otherwise, if any ALLOW rule
// exists for that scope, the IP must match one (allowlist mode) or it is denied.
//
// Enforcement THROWS httpError(403) (like entitlements.assertCan) so a caller
// can never fail open by forgetting to inspect a return value. Every denial
// also emits a deduped, SERVER-AUTHORED anomaly event.

const netip = require('./netip');
const anomaly = require('./anomaly');
const { httpError } = require('./errors');
const { requireAdmin, appendPermissionChange } = require('./entitlements');

// Repeated denials from the same principal coalesce into ONE incident per hour
// (storm control on the append-only ledger + admin email).
const DEDUP_WINDOW_MS = 60 * 60 * 1000;

// Evaluate a set of same-scope rules against a canonical IP.
//  blocked         — an explicit block rule matched
//  denyByAllowlist — allow rules exist for the scope but none matched (allowlist mode)
function evalScope(rules, canonIp) {
  let blocked = false, hasAllow = false, allowMatch = false;
  for (const r of rules) {
    const match = netip.ipInCidr(canonIp, r.cidr);
    if (r.type === 'block') { if (match) blocked = true; }
    else if (r.type === 'allow') { hasAllow = true; if (match) allowMatch = true; }
  }
  return { blocked, denyByAllowlist: hasAllow && !allowMatch };
}

async function deny(ctx, { userId, ip, reason, message }) {
  const canon = netip.canonicalizeIp(ip);
  const principal = userId || netip.ipIdxOf(ctx, canon) || 'noip';
  const bucket = Math.floor(ctx.clock.nowMs() / DEDUP_WINDOW_MS);
  await anomaly.emit(ctx, {
    severity: 'warn', userId, ip, reason,
    detail: `ip=${canon || 'unknown'}`,
    dedupeKey: `anomaly:${reason}:${principal}:${bucket}`,
  });
  throw httpError(403, message);
}

const BLOCK_MSG = 'Access from your network is not allowed.';

// PRE-AUTH global gate. An empty/unknown IP cannot match a block (fail-open on
// block) but fails an allowlist (fail-closed), because evalScope('') never
// matches an allow rule.
async function enforceGlobalIp(ctx, ip) {
  const canon = netip.canonicalizeIp(ip);
  const rules = await ctx.repo.ipRules.find({ scope: 'global' });
  const r = evalScope(rules, canon);
  if (r.blocked) return deny(ctx, { userId: null, ip, reason: anomaly.REASONS.IP_BLOCKED, message: BLOCK_MSG });
  if (r.denyByAllowlist) return deny(ctx, { userId: null, ip, reason: anomaly.REASONS.IP_NOT_ALLOWLISTED, message: BLOCK_MSG });
}

// POST-AUTH per-user gate: per-user ip_rules, then the country DENY-list
// (F2, block beats allow), then the existing allow-list geo-fence (Step 4).
async function enforceUserIp(ctx, user, ip, geo) {
  const canon = netip.canonicalizeIp(ip);
  const rules = await ctx.repo.ipRules.find({ scope: 'user', userId: user._id });
  const r = evalScope(rules, canon);
  if (r.blocked) return deny(ctx, { userId: user._id, ip, reason: anomaly.REASONS.IP_BLOCKED, message: BLOCK_MSG });
  if (r.denyByAllowlist) return deny(ctx, { userId: user._id, ip, reason: anomaly.REASONS.IP_NOT_ALLOWLISTED, message: BLOCK_MSG });
  await enforceCountryBlock(ctx, user, ip, geo);
  await enforceGeoFence(ctx, user, ip, geo);
}

const GEO_BLOCK_MSG = 'Access from your location is not allowed.';

// Country DENY-list (F2): a per-user blacklist, additive alongside the
// existing allow-list geo-fence below. Checked FIRST so a block always wins
// over an allow (mirrors evalScope's "block beats allow" IP precedence).
// FAILS OPEN on an unresolved/unknown country — contrast this with
// enforceGeoFence's fail-CLOSED behavior: a deny-list only ever denies a
// POSITIVELY MATCHED country, never an unprovable one.
async function enforceCountryBlock(ctx, user, ip, geo) {
  const block = user.blockedCountries && Array.isArray(user.blockedCountries.countries) ? user.blockedCountries.countries : null;
  if (!block || block.length === 0) return;
  const blocked = block.map(c => String(c).toUpperCase());
  const country = geo && geo.country ? String(geo.country).toUpperCase() : null;
  if (country && blocked.includes(country)) {
    return deny(ctx, { userId: user._id, ip, reason: anomaly.REASONS.GEO_BLOCKED, message: GEO_BLOCK_MSG });
  }
}

// Geo-fence (Step 4): if the user has an allowed-countries fence, the resolved
// country must be in it. Unknown geo (null / provider error) under an active
// fence FAILS CLOSED — we cannot prove compliance.
async function enforceGeoFence(ctx, user, ip, geo) {
  const fence = user.geoFence && Array.isArray(user.geoFence.countries) ? user.geoFence.countries : null;
  if (!fence || fence.length === 0) return;
  const allowed = fence.map(c => String(c).toUpperCase());
  const country = geo && geo.country ? String(geo.country).toUpperCase() : null;
  if (!country) {
    return deny(ctx, { userId: user._id, ip, reason: anomaly.REASONS.GEO_UNKNOWN_UNDER_FENCE, message: 'Your location could not be verified.' });
  }
  if (!allowed.includes(country)) {
    return deny(ctx, { userId: user._id, ip, reason: anomaly.REASONS.GEO_FENCED, message: GEO_BLOCK_MSG });
  }
}

// --- admin CRUD (recorded in permission_changes) ---------------------------

async function addIpRule(ctx, { adminId, scope, userId, type, cidr, reason, currentIp }) {
  await requireAdmin(ctx, adminId);
  if (scope !== 'global' && scope !== 'user') throw httpError(400, 'scope must be "global" or "user".');
  if (type !== 'allow' && type !== 'block') throw httpError(400, 'type must be "allow" or "block".');
  if (scope === 'user' && !userId) throw httpError(400, 'A user-scoped rule requires a userId.');
  if (scope === 'global' && userId) throw httpError(400, 'A global rule must not carry a userId.');
  if (!netip.isValidCidr(cidr)) throw httpError(400, 'Invalid CIDR.');
  // Self-lockout guard: refuse a global block that matches the admin's own IP.
  if (scope === 'global' && type === 'block' && currentIp && netip.ipInCidr(currentIp, cidr)) {
    throw httpError(400, 'That global block matches your current IP and would lock you out. Remove it via the CLI if this is intended.');
  }
  await appendPermissionChange(ctx, {
    adminId, targetUserId: scope === 'user' ? userId : null,
    field: 'ip_rule_add', from: null, to: `${scope}:${type}:${cidr}`,
  });
  return ctx.repo.ipRules.insert({
    scope, userId: scope === 'user' ? userId : null, type, cidr,
    reason: reason || null, createdBy: adminId, createdAt: ctx.clock.now(),
  });
}

async function removeIpRule(ctx, { adminId, ruleId }) {
  await requireAdmin(ctx, adminId);
  const rule = await ctx.repo.ipRules.findById(ruleId);
  if (!rule) throw httpError(404, 'Rule not found.');
  await appendPermissionChange(ctx, {
    adminId, targetUserId: rule.userId || null,
    field: 'ip_rule_remove', from: `${rule.scope}:${rule.type}:${rule.cidr}`, to: null,
  });
  await ctx.repo.ipRules.deleteById(ruleId);
  return { removed: true, ruleId };
}

async function listIpRules(ctx, { adminId, scope, userId }) {
  await requireAdmin(ctx, adminId);
  const filter = {};
  if (scope) filter.scope = scope;
  if (userId) filter.userId = userId;
  return ctx.repo.ipRules.find(filter);
}

// Set (or clear) a user's geo-fence. Countries are validated + normalized to
// uppercase ISO-3166-1 alpha-2 on write so the enforcement comparison is exact.
// null / [] clears the fence. Recorded in permission_changes.
async function setGeoFence(ctx, { adminId, targetUserId, countries }) {
  await requireAdmin(ctx, adminId);
  const target = await ctx.repo.users.findById(targetUserId);
  if (!target) throw httpError(404, 'User not found.');
  let fence = null;
  if (countries != null) {
    if (!Array.isArray(countries)) throw httpError(400, 'countries must be an array of ISO country codes.');
    const norm = countries.map(c => String(c).trim().toUpperCase());
    if (norm.some(c => !/^[A-Z]{2}$/.test(c))) throw httpError(400, 'Each country must be an ISO-3166-1 alpha-2 code.');
    fence = norm.length ? { countries: [...new Set(norm)] } : null;
  }
  const from = target.geoFence ? JSON.stringify(target.geoFence) : null;
  await appendPermissionChange(ctx, {
    adminId, targetUserId, field: 'geoFence', from, to: fence ? JSON.stringify(fence) : null,
  });
  await ctx.repo.users.updateById(targetUserId, { geoFence: fence, updatedAt: ctx.clock.now() });
  return { targetUserId, geoFence: fence };
}

// Set (or clear) a user's country DENY-list (F2). A bespoke setter following
// setGeoFence's shape byte-for-byte (requireAdmin, validate/normalize ISO
// codes, null/[] clears, appendPermissionChange) — NO CORE_FIELDS/
// MUTABLE_FIELDS change, exactly like geoFence above.
async function setBlockedCountries(ctx, { adminId, targetUserId, countries }) {
  await requireAdmin(ctx, adminId);
  const target = await ctx.repo.users.findById(targetUserId);
  if (!target) throw httpError(404, 'User not found.');
  let blocked = null;
  if (countries != null) {
    if (!Array.isArray(countries)) throw httpError(400, 'countries must be an array of ISO country codes.');
    const norm = countries.map(c => String(c).trim().toUpperCase());
    if (norm.some(c => !/^[A-Z]{2}$/.test(c))) throw httpError(400, 'Each country must be an ISO-3166-1 alpha-2 code.');
    blocked = norm.length ? { countries: [...new Set(norm)] } : null;
  }
  const from = target.blockedCountries ? JSON.stringify(target.blockedCountries) : null;
  await appendPermissionChange(ctx, {
    adminId, targetUserId, field: 'blockedCountries', from, to: blocked ? JSON.stringify(blocked) : null,
  });
  await ctx.repo.users.updateById(targetUserId, { blockedCountries: blocked, updatedAt: ctx.clock.now() });
  return { targetUserId, blockedCountries: blocked };
}

module.exports = {
  enforceGlobalIp, enforceUserIp, enforceGeoFence, enforceCountryBlock,
  addIpRule, removeIpRule, listIpRules, setGeoFence, setBlockedCountries, evalScope,
};
