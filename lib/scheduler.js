'use strict';
// Periodic maintenance scheduler (closes gap #1). One tick:
//   1. Anchor BOTH chains (audit_events + permission_changes) — head-pinning.
//   2. Verify BOTH chains; a broken chain emits a CRITICAL chain-verify anomaly
//      (admin alert) and that chain is NOT pruned (preserve the evidence).
//   3. Anchor-aligned prune of BOTH chains for events past the retention window.
//
// runMaintenance() is a pure-ish async function driven by the injected clock, so
// it is fully unit-testable. start() wires it to a real interval for production;
// the CLI (`node cli.js maintain`) runs a single tick on demand.

const audit = require('./audit');
const entitlements = require('./entitlements');
const retention = require('./retention');
const anomaly = require('./anomaly');
const { redactSensitive } = require('./errors');

async function verifyAndMaybeAlert(ctx, { verify, label }) {
  const res = await verify();
  if (!res.ok) {
    await anomaly.emit(ctx, {
      severity: 'critical', reason: anomaly.REASONS.CHAIN_VERIFY_FAILED,
      detail: `${label} chain: ${res.reason}${res.seq != null ? ' @seq ' + res.seq : ''}`,
      dedupeKey: `anomaly:chain_verify_failed:${label}:${res.reason}:${res.seq != null ? res.seq : ''}`,
    });
  }
  return res.ok;
}

async function runMaintenance(ctx) {
  // 1. Anchor (head-pin) both chains.
  const auditAnchor = await audit.anchorNow(ctx);
  const permAnchor = await audit.anchorPermsNow(ctx);

  // 2. Verify both; alert + skip-prune on failure.
  const auditOk = await verifyAndMaybeAlert(ctx, { verify: () => audit.verifyAuditChain(ctx), label: 'audit' });
  const permOk = await verifyAndMaybeAlert(ctx, { verify: () => entitlements.verifyPermissionChain(ctx), label: 'permission' });

  // 3. Anchor-aligned prune of the verified chains only. Anchoring (above) and
  // verify (above) always read/write through ctx.repo — the APP role
  // (insert+find, never delete on the ledgers). The prune's DELETE is routed
  // through ctx.pruneRepo when Phase 6 Task 3 configured a separate
  // delete-capable Mongo connection (MONGODB_PRUNE_URI → context.js), falling
  // back to ctx.repo when it did not — the exact single-connection behavior
  // from before this task.
  const deleteRepo = ctx.pruneRepo || ctx.repo;
  const rd = ctx.config.retentionDays;
  const prunedAudit = auditOk
    ? await retention.pruneAnchorAligned(ctx, {
        events: ctx.repo.auditEvents, anchors: ctx.repo.auditAnchors, retentionDays: rd,
        deleteEvents: deleteRepo.auditEvents,
      })
    : { pruned: 0, skipped: 'verify_failed' };
  const prunedPerm = permOk
    ? await retention.pruneAnchorAligned(ctx, {
        events: ctx.repo.permissionChanges, anchors: ctx.repo.permAnchors, retentionDays: rd,
        deleteEvents: deleteRepo.permissionChanges,
      })
    : { pruned: 0, skipped: 'verify_failed' };

  return { auditAnchor, permAnchor, auditOk, permOk, prunedAudit, prunedPerm };
}

// Start the interval in production. Returns { stop }. Never lets a failed tick
// crash the process; the interval is unref'd so it doesn't hold the event loop.
function start(ctx, { intervalMs } = {}) {
  const ms = intervalMs || ctx.config.pruneIntervalMs;
  const timer = setInterval(() => {
    runMaintenance(ctx).catch(err => {
      if (ctx.logger && ctx.logger.error) ctx.logger.error(redactSensitive('maintenance tick failed: ' + (err && err.message)));
    });
  }, ms);
  if (timer.unref) timer.unref();
  return { stop: () => clearInterval(timer) };
}

module.exports = { runMaintenance, start };
