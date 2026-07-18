'use strict';
// Remote-command queue (spec §6.7). Commands live in their OWN collection (one
// doc per commandId) rather than an embedded devices.pendingCommands array, so
// enqueue / poll / ack are all atomic with the repo's existing primitives
// (insert + CAS updateOne) — no embedded-array lost-update race.
//
// UNILATERAL SECURITY EFFECTS AT ENQUEUE: deprovision / disable / force-logout
// take effect on the SERVER the instant the admin enqueues — sessions revoked,
// status flipped through the permission_changes ledger — never waiting for the
// device to poll (a device that never checks in must still be cut off). The
// device ack is best-effort delivery confirmation only.
//
// AUTHORIZATION: only an admin enqueues; a device may poll/ack only commands for
// ITS OWN deviceId (taken from the verified token's `did`) owned by ITS OWN
// user. REPLAY-SAFE: ack is an idempotent CAS; a replayed ack is a no-op and
// writes at most one transition audit event (idempotency-keyed).

const crypto = require('crypto');
const audit = require('./audit');
const authLib = require('./auth');
const { requireAdmin, appendPermissionChange } = require('./entitlements');
const { httpError } = require('./errors');

const COMMAND_TYPES = new Set(['wipe_claude_creds', 'deprovision', 'force_logout', 'disable_account']);
const COMMAND_EVENT = {
  wipe_claude_creds: 'remote_wipe',
  deprovision: 'remote_deprovision',
  force_logout: 'remote_force_logout',
  disable_account: 'remote_disable',
};

async function setUserStatus(ctx, adminId, userId, status) {
  const user = await ctx.repo.users.findById(userId);
  if (!user) return;
  // Chain the status change in permission_changes (Phase-1 invariant) BEFORE
  // applying, so an admin-driven deprovision/disable is provable there too.
  await appendPermissionChange(ctx, { adminId, targetUserId: userId, field: 'status', from: user.status, to: status });
  await ctx.repo.users.updateById(userId, { status, updatedAt: ctx.clock.now() });
}

// Apply the command's server-side effect synchronously (unilateral).
async function applyServerEffects(ctx, { adminId, type, userId, device, now }) {
  if (type === 'force_logout') {
    await authLib.revokeAllForUser(ctx, userId, now, 'force_logout');
  } else if (type === 'deprovision') {
    await setUserStatus(ctx, adminId, userId, 'deprovisioned');
    await authLib.revokeAllForUser(ctx, userId, now, 'deprovision');
    await ctx.repo.devices.updateById(device._id, { status: 'deprovisioned', updatedAt: now });
  } else if (type === 'disable_account') {
    await setUserStatus(ctx, adminId, userId, 'suspended');
    await authLib.revokeAllForUser(ctx, userId, now, 'disable_account');
  } else if (type === 'wipe_claude_creds') {
    await ctx.repo.devices.updateById(device._id, { status: 'wiped', updatedAt: now });
  }
}

async function enqueueCommand(ctx, { adminId, deviceId, type }) {
  await requireAdmin(ctx, adminId);
  if (!COMMAND_TYPES.has(type)) throw httpError(400, 'Unknown command type.');
  const device = await ctx.repo.devices.findById(deviceId);
  if (!device) throw httpError(404, 'Device not found.');
  const userId = device.userId;
  const now = ctx.clock.now();
  const commandId = crypto.randomUUID();

  await applyServerEffects(ctx, { adminId, type, userId, device, now });

  await ctx.repo.commands.insert({
    _id: commandId, deviceId, userId, type, status: 'pending',
    issuedBy: adminId, issuedAt: now, sentAt: null, ackedAt: null, result: null,
  });
  await audit.recordEvent(ctx, {
    eventType: COMMAND_EVENT[type], userId, deviceId,
    commandId, commandType: type, commandStatus: 'pending',
    idempotencyKey: `cmd:${commandId}:pending`,
  });
  return { commandId, type, status: 'pending' };
}

// Device fetches its pending/undelivered commands (deviceId from the token did).
// Pending commands are CAS'd to 'sent' and audited once; already-'sent' commands
// are RE-DELIVERED (at-least-once) until acked, without a duplicate audit row.
async function pollCommands(ctx, { userId, deviceId }) {
  if (!deviceId) throw httpError(400, 'Missing device id.');
  const device = await ctx.repo.devices.findById(deviceId);
  if (device && device.userId !== userId) throw httpError(403, 'Not your device.');
  const now = ctx.clock.now();
  // Scope the query by BOTH deviceId and userId (mirrors ackCommand's dual check)
  // so a caller can never see or transition a command belonging to another user,
  // even if a deviceId were reused across accounts.
  const active = await ctx.repo.commands.find({ deviceId, userId, status: { $in: ['pending', 'sent'] } });
  const out = [];
  for (const c of active) {
    if (c.status === 'pending') {
      const won = await ctx.repo.commands.updateOne({ _id: c._id, status: 'pending' }, { $set: { status: 'sent', sentAt: now } });
      if (won) {
        await audit.recordEvent(ctx, {
          eventType: COMMAND_EVENT[c.type], userId: c.userId, deviceId,
          commandId: c._id, commandType: c.type, commandStatus: 'sent',
          idempotencyKey: `cmd:${c._id}:sent`,
        });
      }
    }
    out.push({ commandId: c._id, type: c.type });
  }
  if (device) await ctx.repo.devices.updateById(deviceId, { lastSeen: now, monitoringLastAt: now });
  return { commands: out };
}

async function ackCommand(ctx, { userId, deviceId, commandId, result }) {
  if (!deviceId) throw httpError(400, 'Missing device id.');
  const cmd = await ctx.repo.commands.findById(commandId);
  if (!cmd) throw httpError(404, 'Command not found.');
  // The command must target THIS device (token did) owned by THIS user — a
  // user's OTHER device cannot ack a command aimed at the first (device-grained).
  if (cmd.deviceId !== deviceId || cmd.userId !== userId) throw httpError(403, 'Not your command.');
  const now = ctx.clock.now();
  const status = result === 'failed' ? 'failed' : 'acked';
  // CAS pending/sent → acked/failed exactly once; a replayed ack loses the CAS.
  const won = await ctx.repo.commands.updateOne(
    { _id: commandId, status: { $in: ['pending', 'sent'] } },
    { $set: { status, ackedAt: now, result: result || 'ok' } },
  );
  if (won) {
    await audit.recordEvent(ctx, {
      eventType: COMMAND_EVENT[cmd.type], userId, deviceId,
      commandId, commandType: cmd.type, commandStatus: status,
      idempotencyKey: `cmd:${commandId}:${status}`,
    });
  }
  return { commandId, status: won ? status : cmd.status, idempotent: !won };
}

module.exports = { enqueueCommand, pollCommands, ackCommand, COMMAND_TYPES, COMMAND_EVENT };
