'use strict';
// Email one-time passcodes (OTP).
//
//  - 6-digit codes from a CSPRNG (crypto.randomInt — uniform, no modulo bias).
//  - Stored only as a KEYED hash (HMAC via the field-crypto blind index),
//    bound to userId+purpose+code, so a DB leak does not reveal codes and codes
//    can't be replayed across users/purposes. The plaintext code exists only in
//    the outbound email.
//  - 5-minute TTL, per-code attempt cap, and a per-user+purpose send rate limit.
//  - Issuing a new code invalidates prior unconsumed codes (one live code).
//
// Anti-enumeration: verify returns a single generic error for "no such code",
// "wrong code", and "expired" so callers cannot distinguish them.

const crypto = require('crypto');
const { httpError } = require('./errors');

function generateCode(length = 6) {
  const max = 10 ** length;
  return String(crypto.randomInt(0, max)).padStart(length, '0');
}

// Keyed hash binding code to the specific user + purpose.
function codeHashOf(ctx, userId, purpose, code) {
  return ctx.crypto.blindIndex(`otp:${userId}:${purpose}:${String(code)}`);
}

async function issueOtp(ctx, { userId, purpose, email }) {
  const now = ctx.clock.now();
  const { ttlMs, maxSendsPerWindow, rateWindowMs, length } = ctx.config.otp;

  // Send rate limit (per user + purpose) over the rolling window.
  const windowStart = new Date(now.getTime() - rateWindowMs);
  const recentSends = await ctx.repo.otps.count({ userId, purpose, createdAt: { $gte: windowStart } });
  if (recentSends >= maxSendsPerWindow) {
    throw httpError(429, 'Too many codes requested. Please wait a few minutes and try again.');
  }

  // Invalidate prior unconsumed codes so only the newest is live.
  const priors = await ctx.repo.otps.find({ userId, purpose, consumedAt: null });
  for (const p of priors) await ctx.repo.otps.updateById(p._id, { consumedAt: now });

  const code = generateCode(length);
  const doc = await ctx.repo.otps.insert({
    userId,
    purpose,
    codeHash: codeHashOf(ctx, userId, purpose, code),
    expiresAt: new Date(now.getTime() + ttlMs),
    attempts: 0,
    consumedAt: null,
    createdAt: now,
  });

  await ctx.mailer.send({
    to: email,
    subject: 'Your Managed Switcher verification code',
    text: `Your verification code is ${code}\n\n`
      + `It expires in ${Math.round(ttlMs / 60000)} minutes. `
      + `If you didn't request this, you can ignore this email.`,
  });

  return { otpId: doc._id, expiresAt: doc.expiresAt };
}

async function verifyOtp(ctx, { userId, purpose, code }) {
  const now = ctx.clock.now();
  const invalid = () => httpError(400, 'Invalid or expired code.');

  const active = (await ctx.repo.otps.find({ userId, purpose, consumedAt: null }))
    .sort((a, b) => b.createdAt - a.createdAt);
  const doc = active[0];
  if (!doc) throw invalid();
  if (doc.expiresAt <= now) throw invalid();

  // ATOMIC guarded increment: burns one attempt only while under the cap AND
  // still unconsumed. Returns null if the cap is already hit or the code was
  // consumed — so concurrent verifies can never exceed maxAttempts guesses
  // (no read-then-write TOCTOU). Enforces the brute-force budget in production.
  const bumped = await ctx.repo.otps.updateOne(
    { _id: doc._id, consumedAt: null, attempts: { $lt: ctx.config.otp.maxAttempts } },
    { $inc: { attempts: 1 } },
  );
  if (!bumped) throw httpError(429, 'Too many attempts. Request a new code.');

  const expected = Buffer.from(bumped.codeHash);
  const actual = Buffer.from(codeHashOf(ctx, userId, purpose, code));
  const ok = expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  if (!ok) throw invalid();

  // ATOMIC single-use consume: only the first correct guess wins.
  const consumed = await ctx.repo.otps.updateOne(
    { _id: doc._id, consumedAt: null },
    { $set: { consumedAt: now } },
  );
  if (!consumed) throw invalid();
  return { userId, purpose };
}

module.exports = { generateCode, issueOtp, verifyOtp };
