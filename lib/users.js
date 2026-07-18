'use strict';
// users repository logic: creation, lookup, and the field mapping between the
// public shape and the encrypted at-rest shape.
//
// At rest a user NEVER stores plaintext email or plaintext password:
//   emailEnc  = AES-256-GCM(normalizedEmail)   (admin-decryptable PII)
//   emailIdx  = HMAC blind index               (unique equality lookup)
//   passwordHash = scrypt(...)
// New users default to importEnabled=exportEnabled=false and status='pending'.

const crypto = require('crypto');
const { normalizeEmail, isValidEmail } = require('./email');
const { hashPassword } = require('./passwords');
const { httpError } = require('./errors');

const MIN_PASSWORD_LEN = 8;

// AAD binding emailEnc to the owning record, so a ciphertext cannot be silently
// relocated to a different user row (#21). The _id is minted before insert.
function emailAad(id) {
  return 'email:' + id;
}

async function createUser(ctx, { email, password, role = 'member' }) {
  const norm = normalizeEmail(email);
  if (!isValidEmail(norm)) throw httpError(400, 'Enter a valid email address.');
  if (!password || String(password).length < MIN_PASSWORD_LEN) {
    throw httpError(400, `Password must be at least ${MIN_PASSWORD_LEN} characters.`);
  }

  const emailIdx = ctx.crypto.blindIndex(norm);
  // Service-level uniqueness check; Mongo also has a unique index on emailIdx
  // as the race backstop (see mongoRepo.js).
  const existing = await ctx.repo.users.findOne({ emailIdx });
  if (existing) throw httpError(409, 'An account with that email already exists.');

  const now = ctx.clock.now();
  // Mint the _id up front so emailEnc's AAD can bind the ciphertext to THIS
  // record. Uniqueness is enforced on emailIdx (not _id), so the DUPLICATE_EMAIL
  // race backstop is unaffected by supplying our own _id.
  const _id = crypto.randomUUID();
  const user = {
    _id,
    emailIdx,
    emailEnc: ctx.crypto.encrypt(norm, emailAad(_id)),
    passwordHash: hashPassword(password, ctx.config.scrypt),
    role: role === 'admin' ? 'admin' : 'member',
    status: 'pending',
    emailVerified: false,
    importEnabled: false,
    exportEnabled: false,
    entitlementExpiresAt: null,
    exportQuota: { maxPerDay: 0, used: 0, windowStart: now },
    failedLogins: 0,
    lockedUntil: null,
    noticeAcceptedAt: null,
    noticeVersion: null,
    geoFence: null,
    blockedCountries: null, // F2: per-user country deny-list, additive alongside geoFence
    monitoringEnabled: true, // managed tool: on by default; admin may disable per user (Step 8)
    alertsEnabled: true, // admin email notifications for this user's anomalies; on by default (E3)
    createdAt: now,
    updatedAt: now,
  };
  try {
    return await ctx.repo.users.insert(user);
  } catch (err) {
    // Unique-index backstop for the check-then-insert race (two concurrent
    // signups for the same email): surface a clean 409, never a 500.
    if (err && err.code === 'DUPLICATE_EMAIL') {
      throw httpError(409, 'An account with that email already exists.');
    }
    throw err;
  }
}

async function findUserByEmail(ctx, email) {
  const emailIdx = ctx.crypto.blindIndex(normalizeEmail(email));
  return ctx.repo.users.findOne({ emailIdx });
}

function decryptEmail(ctx, user) {
  return ctx.crypto.decrypt(user.emailEnc, emailAad(user._id));
}

module.exports = { createUser, findUserByEmail, decryptEmail, emailAad, MIN_PASSWORD_LEN };
