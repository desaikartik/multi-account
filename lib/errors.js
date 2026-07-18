'use strict';
// Typed HTTP errors. Services throw these; the HTTP layer maps .status → code
// and returns { error: .message }. Messages are user-facing and MUST NOT
// contain tokens, PII, secrets, or stack details.

function httpError(status, message, extra = {}) {
  const err = new Error(message);
  err.status = status;
  err.expose = true; // safe to send to the client
  Object.assign(err, extra);
  return err;
}

// Redact secrets before an (unexpected) error message is written to a log.
// Mongo driver errors, in particular, can embed the connection string WITH
// credentials; and any long opaque token/key/hash is redacted defensively.
function redactSensitive(input) {
  let s = String(input == null ? '' : input);
  // scheme://user:pass@host  →  scheme://[redacted]@host
  //
  // Greedy-then-backtrack: [^\s/]* first grabs every non-space/non-slash char
  // after "scheme://", then backtracks to the LAST '@' in that run before
  // requiring the literal '@'. A real host is never allowed to contain '@', so
  // that rightmost '@' is always the true credentials/host boundary — even
  // when the password itself contains ':' or '@' (e.g. "user:P@ssw0rd@host"),
  // which the previous [^\s:@/]+:[^\s:@/]+@ shape stopped at the FIRST '@',
  // silently leaving the tail of such a password (e.g. "ssw0rd") unredacted.
  s = s.replace(/([a-zA-Z][\w+.-]*:\/\/)[^\s/]*@/g, '$1[redacted]@');
  // long opaque runs (base64/base64url/hex: keys, JWT segments, hashes)
  s = s.replace(/[A-Za-z0-9+/_-]{24,}={0,2}/g, '[redacted]');
  return s;
}

module.exports = { httpError, redactSensitive };
