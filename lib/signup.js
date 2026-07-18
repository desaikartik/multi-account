'use strict';
// Signup: syntax + policy gate (disposable domain, MX check), then create a
// pending user. OTP issuance is layered on in step 4 (issueSignupOtp).
//
// Order matters: fail fast on cheap local checks BEFORE any DNS lookup, so
// garbage input never triggers network traffic.

const { normalizeEmail, isValidEmail, emailDomain } = require('./email');
const { isDisposableDomain } = require('./disposable-domains');
const { createUser, findUserByEmail, MIN_PASSWORD_LEN } = require('./users');
const { verifyOtp } = require('./otp'); // still used by the legacy verifySignup path below
const { httpError } = require('./errors');

// Deliverability check: MX first, then A/AAAA implicit-MX fallback (a domain
// with only an address record still receives mail, RFC 5321 §5.1). Fails CLOSED:
// no MX and no address record (or DNS errors) → treated as undeliverable.
async function domainCanReceiveMail(ctx, domain) {
  try {
    const mx = await ctx.resolveMx(domain);
    if (Array.isArray(mx) && mx.length > 0) return true;
  } catch { /* fall through to A/AAAA */ }
  if (typeof ctx.resolveHost === 'function') {
    try {
      const hosts = await ctx.resolveHost(domain);
      if (Array.isArray(hosts) && hosts.length > 0) return true;
    } catch { /* undeliverable */ }
  }
  return false;
}

async function signup(ctx, { email, password }) {
  const norm = normalizeEmail(email);
  if (!isValidEmail(norm)) throw httpError(400, 'Enter a valid email address.');
  if (!password || String(password).length < MIN_PASSWORD_LEN) {
    throw httpError(400, `Password must be at least ${MIN_PASSWORD_LEN} characters.`);
  }

  const domain = emailDomain(norm);
  if (isDisposableDomain(domain)) {
    throw httpError(422, 'Please sign up with a permanent email address; disposable/temporary email domains are not allowed.');
  }
  if (!(await domainCanReceiveMail(ctx, domain))) {
    throw httpError(422, "That email domain can't receive mail. Check the address and try again.");
  }

  // No OTP: the account is created PENDING and cannot sign in until an ADMIN
  // approves it (admin.approveUser). In this managed product, admin approval
  // replaces self-service email verification — the admin vouches for the user.
  const user = await createUser(ctx, { email: norm, password });
  // Response carries NO email or hash — only a reference + the pending status.
  return { userId: user._id, status: user.status, emailVerified: user.emailVerified, pendingApproval: true };
}

// Confirm the signup OTP → activate the account. Takes email (not userId) as
// the client would; unknown emails yield the SAME generic error as a bad code
// so account existence is never revealed.
async function verifySignup(ctx, { email, code }) {
  const user = await findUserByEmail(ctx, normalizeEmail(email));
  if (!user) throw httpError(400, 'Invalid or expired code.');
  await verifyOtp(ctx, { userId: user._id, purpose: 'signup', code });
  await ctx.repo.users.updateById(user._id, {
    status: 'active',
    emailVerified: true,
    updatedAt: ctx.clock.now(),
  });
  return { status: 'active', emailVerified: true };
}

module.exports = { signup, verifySignup, domainCanReceiveMail };
