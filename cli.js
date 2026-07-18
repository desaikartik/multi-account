#!/usr/bin/env node
'use strict';
// Seed / admin CLI.
//
//   node cli.js keygen                      Print a ready-to-paste .env with fresh keys.
//   node cli.js create-admin <email> [pw]   Create the first admin (prompts for pw if omitted).
//   node cli.js verify-audit                Walk + verify the audit hash chain.
//
// create-admin / verify-audit use the same composition root as the server
// (context.js), so REPO=memory works for a dry run and the default (Mongo)
// creates the real admin.

const readline = require('readline');
const { buildEnvTemplate } = require('./lib/config');
const { redactSensitive } = require('./lib/errors');
const admin = require('./lib/admin');
const audit = require('./lib/audit');

function prompt(question, { hidden = false } = {}) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    if (hidden) {
      // Best-effort masking: suppress echo while typing the password.
      const onData = () => { rl.output.write('\x1b[2K\r' + question); };
      rl.input.on('data', onData);
      rl.question(question, answer => { rl.input.off('data', onData); rl.output.write('\n'); rl.close(); resolve(answer); });
    } else {
      rl.question(question, answer => { rl.close(); resolve(answer); });
    }
  });
}

async function cmdKeygen() {
  process.stdout.write(buildEnvTemplate(process.env).text);
}

async function cmdCreateAdmin(args) {
  const { createContext } = require('./context');
  const ctx = await createContext();
  const email = args[0] || await prompt('Admin email: ');
  const password = args[1] || await prompt('Admin password (min 8 chars): ', { hidden: true });
  if (await admin.hasAdmin(ctx)) {
    process.stderr.write('Note: an admin already exists; creating another.\n');
  }
  const res = await admin.createAdmin(ctx, { email, password });
  process.stdout.write(`Created admin ${res.userId} (${email}).\n`);
  if (ctx.repo.close) await ctx.repo.close();
}

async function cmdVerifyAudit() {
  const { createContext } = require('./context');
  const ctx = await createContext();
  const res = await audit.verifyAuditChain(ctx);
  process.stdout.write(JSON.stringify(res, null, 2) + '\n');
  if (ctx.repo.close) await ctx.repo.close();
  if (!res.ok) process.exitCode = 2;
}

// Anchor the current audit chain head. Signs {seqHigh, headHash} with the
// Ed25519 anchor key.
async function cmdAnchor() {
  const { createContext } = require('./context');
  const ctx = await createContext();
  const anchor = await audit.anchorNow(ctx);
  process.stdout.write(anchor
    ? `Anchored seqHigh=${anchor.seqHigh} at ${new Date(anchor.anchoredAt).toISOString()}\n`
    : 'No audit events to anchor yet.\n');
  if (ctx.repo.close) await ctx.repo.close();
}

// Run one maintenance tick: anchor BOTH chains, verify them (critical anomaly on
// tamper), and anchor-aligned-prune events past the 7-day window. Intended for a
// daily cron on the serverless target. The prune deletes ledger rows, so in
// production it must run with a connection whose role permits delete on
// audit_events/permission_changes — kept OUT of the app's insert+find-only
// role. Phase 6 Task 3: createContext() already builds ctx.pruneRepo (a
// separate connection under that privileged role) whenever MONGODB_PRUNE_URI
// is configured, and scheduler.runMaintenance(ctx) itself selects
// ctx.pruneRepo || ctx.repo for the delete — this CLI just needs to close
// BOTH connections it may have opened.
async function cmdMaintain() {
  const { createContext } = require('./context');
  const scheduler = require('./lib/scheduler');
  const ctx = await createContext();
  const r = await scheduler.runMaintenance(ctx);
  process.stdout.write(JSON.stringify({
    auditOk: r.auditOk, permOk: r.permOk,
    prunedAudit: r.prunedAudit, prunedPerm: r.prunedPerm,
    auditAnchor: r.auditAnchor ? r.auditAnchor.seqHigh : null,
    permAnchor: r.permAnchor ? r.permAnchor.seqHigh : null,
  }, null, 2) + '\n');
  // The prune (delete-capable) connection, when configured, is a SEPARATE
  // connection from the app repo and must be closed independently — closing
  // ctx.repo alone would leak it.
  if (ctx.pruneRepo && ctx.pruneRepo.close) await ctx.pruneRepo.close();
  if (ctx.repo.close) await ctx.repo.close();
  if (!r.auditOk || !r.permOk) process.exitCode = 2;
}

// Verify the permission_changes chain (admin console tamper check).
async function cmdVerifyPerms() {
  const { createContext } = require('./context');
  const entitlements = require('./lib/entitlements');
  const ctx = await createContext();
  const res = await entitlements.verifyPermissionChain(ctx);
  process.stdout.write(JSON.stringify(res, null, 2) + '\n');
  if (ctx.repo.close) await ctx.repo.close();
  if (!res.ok) process.exitCode = 2;
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  switch (cmd) {
    case 'keygen': return cmdKeygen();
    case 'create-admin': return cmdCreateAdmin(args);
    case 'verify-audit': return cmdVerifyAudit();
    case 'verify-perms': return cmdVerifyPerms();
    case 'anchor': return cmdAnchor();
    case 'maintain': return cmdMaintain();
    default:
      process.stderr.write('Usage: node cli.js <keygen|create-admin <email> [password]|verify-audit|verify-perms|anchor|maintain>\n');
      process.exitCode = 1;
  }
}

if (require.main === module) {
  // SEC-1: a Mongo connect/URI error can embed MONGODB_URI WITH credentials —
  // redact before this ever reaches stderr/a log, same as every other
  // logger.error call in the backend.
  main().catch(err => { console.error(redactSensitive(err && err.message)); process.exit(1); });
}

module.exports = { main };
