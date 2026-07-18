'use strict';
// Email normalization + validation. Step 3 extends this module with the
// disposable-domain blocklist and the MX-record check.

// Normalize for storage/dedup: trim, lowercase, and strip a single trailing dot
// (the FQDN form user@domain.com. resolves to the same mailbox, so it must not
// bypass the disposable blocklist or create a duplicate account). Deliberately
// does NOT strip Gmail dots/plus-tags — that can merge distinct accounts.
function normalizeEmail(raw) {
  return String(raw == null ? '' : raw).trim().toLowerCase().replace(/\.$/, '');
}

// Pragmatic syntax check (full RFC 5322 is not worth it; the MX check in
// step 3 does the real "can this receive mail" verification).
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isValidEmail(email) {
  const e = normalizeEmail(email);
  return e.length > 0 && e.length <= 254 && EMAIL_RE.test(e);
}

// Extract the domain (after the last @), lowercased. '' if none.
function emailDomain(email) {
  const e = normalizeEmail(email);
  const at = e.lastIndexOf('@');
  return at === -1 ? '' : e.slice(at + 1);
}

module.exports = { normalizeEmail, isValidEmail, emailDomain };
