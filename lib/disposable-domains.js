'use strict';
// Maintained blocklist of disposable / throwaway email domains. Signup rejects
// these (see signup.js). Kept small and curated on purpose — extend as needed.
// Matching is case-insensitive and covers subdomains (e.g. inbox.mailinator.com).

const DISPOSABLE_DOMAINS = new Set([
  '10minutemail.com',
  '20minutemail.com',
  'anonbox.net',
  'dispostable.com',
  'fakeinbox.com',
  'getairmail.com',
  'getnada.com',
  'guerrillamail.com',
  'guerrillamail.net',
  'guerrillamail.org',
  'harakirimail.com',
  'inboxbear.com',
  'jetable.org',
  'mailcatch.com',
  'maildrop.cc',
  'mailinator.com',
  'mailnesia.com',
  'mintemail.com',
  'moakt.com',
  'mohmal.com',
  'mytemp.email',
  'nada.email',
  'sharklasers.com',
  'spam4.me',
  'spamgourmet.com',
  'temp-mail.org',
  'tempmail.com',
  'tempmailo.com',
  'tempr.email',
  'throwawaymail.com',
  'trashmail.com',
  'trashmail.de',
  'yopmail.com',
  'yopmail.net',
  'mail-temp.com',
  'discard.email',
  'emailondeck.com',
  'fakemail.net',
  'burnermail.io',
  'tmail.io',
]);

function isDisposableDomain(domain) {
  // Strip a trailing dot (FQDN form) so example.com. matches example.com.
  const d = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
  if (!d) return false;
  if (DISPOSABLE_DOMAINS.has(d)) return true;
  // Subdomain match: sub.mailinator.com → matches mailinator.com.
  for (const blocked of DISPOSABLE_DOMAINS) {
    if (d.endsWith('.' + blocked)) return true;
  }
  return false;
}

module.exports = { isDisposableDomain, DISPOSABLE_DOMAINS };
