'use strict';
// Task 8 (Phase 4 / Addendum B#4): a per-PC ENCRYPTED SERVER COPY of the
// device's Claude saved-account store. Admin-only visibility; encrypted at
// rest with the server field-crypto key (ctx.crypto), never returned to the
// owning user. The client vault + upload wiring is a separate task — this
// module is storage + read only.
//
// AAD BINDING: mirrors netip.encryptIp's record-bound-AAD pattern. The blob is
// encrypted with AAD `claude:<deviceId>`, so it cannot be silently relocated
// to a different device record and decrypted there — a moved/mismatched blob
// fails AES-GCM tag verification (tamper-evidence).
//
// OWNERSHIP GUARD: mirrors presence.js — a device already owned by a
// DIFFERENT user must never be overwritten by a second user's upload. Refused
// with 409 (no silent takeover, no silent overwrite).
//
// DECRYPT-FAILURE SEMANTICS (chosen + documented, see task brief): a corrupt
// or wrong-AAD blob is NEVER swallowed into a fake "no cred" response — that
// would hide tampering as if the device simply had no cred on file. Instead
// ctx.crypto.decrypt's exception is left to propagate out of readClaudeCred
// so the caller (the admin route) surfaces it as a hard error, not a payload.

const { httpError } = require('./errors');

function aadFor(deviceId) {
  return 'claude:' + String(deviceId == null ? '' : deviceId);
}

// Store (insert or update in place) the device's encrypted Claude-cred blob.
// deviceId/userId MUST come from the verified access token at the call site
// (never the request body) — see routes.js hPutDeviceClaudeCred.
async function storeClaudeCred(ctx, { deviceId, userId, payload }) {
  const enc = ctx.crypto.encrypt(JSON.stringify(payload), aadFor(deviceId));
  const now = ctx.clock.now();
  const dev = await ctx.repo.devices.findById(deviceId);

  if (dev) {
    // Ownership guard (mirrors presence.js): never let a second user's upload
    // overwrite a device record already owned by someone else.
    if (dev.userId && dev.userId !== userId) {
      throw httpError(409, 'Device is registered to another user.');
    }
    await ctx.repo.devices.updateById(deviceId, {
      claudeCredEnc: enc, claudeCredAt: now, updatedAt: now,
    });
  } else {
    // Minimal doc — presence/heartbeat fill in the rest (firstSeen/lastSeen/
    // geo/etc.) on the device's next check-in.
    await ctx.repo.devices.insert({
      _id: deviceId, userId, claudeCredEnc: enc, claudeCredAt: now,
      firstSeen: now, lastSeen: now, status: 'active',
    });
  }
  return { ok: true };
}

// Admin-only read: decrypt the stored blob with the record-bound AAD.
// A missing device / missing blob is a normal "nothing on file" result. A
// decrypt failure (wrong AAD / corrupted ciphertext) is NOT that — it throws,
// per the tamper-evidence semantics documented above.
async function readClaudeCred(ctx, { deviceId }) {
  const dev = await ctx.repo.devices.findById(deviceId);
  if (!dev || !dev.claudeCredEnc) {
    return { deviceId, payload: null, claudeCredAt: null };
  }
  const payload = JSON.parse(ctx.crypto.decrypt(dev.claudeCredEnc, aadFor(deviceId)));
  return { deviceId, payload, claudeCredAt: dev.claudeCredAt || null };
}

module.exports = { storeClaudeCred, readClaudeCred };
