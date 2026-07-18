'use strict';
// Static serving for the admin web console (Phase 5, Addendum B#6: strictly
// view-only, client-rendered, served same-origin so no CORS layer is ever
// needed for the console's own APIs — see lib/httpsec.js).
//
// webStatic(urlPath) is a PURE explicit allowlist lookup — never joins user
// input into a filesystem path, so directory traversal is structurally
// impossible: only the exact literal keys below ever resolve to a file, and
// anything else (including a path containing `..`) resolves to null and
// falls through to the ordinary API 404.
//
// Files are read fresh per request by the caller (server.js), matching the
// root engine's convention (lib/server.js STATIC map) so edits to
// backend/public/ take effect without a server restart.

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// Verbatim from the Phase 5 task brief. Served on EVERY static hit, in
// addition to the per-file Content-Type below.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const STATIC_HEADERS = {
  'Content-Security-Policy': CSP,
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

// url path -> [file in backend/public/, Content-Type]. Explicit allowlist
// only — do NOT generalize this into a path.join(PUBLIC_DIR, urlPath) lookup;
// that would reopen the exact traversal hole this module exists to close.
const ALLOWLIST = {
  '/console': ['admin.html', 'text/html; charset=utf-8'],
  '/console/': ['admin.html', 'text/html; charset=utf-8'],
  '/console/admin.js': ['admin.js', 'text/javascript'],
  '/console/admin.css': ['admin.css', 'text/css'],
  '/console/adminviews.js': ['adminviews.js', 'text/javascript'],
};

// Resolve a request path to { file, contentType }, or null if it is not one
// of the explicit allowlisted console assets.
function webStatic(urlPath) {
  const entry = ALLOWLIST[urlPath];
  if (!entry) return null;
  const [file, contentType] = entry;
  return { file, contentType };
}

// Read an allowlisted file's bytes fresh off disk. `file` MUST come from a
// webStatic() result (a literal from ALLOWLIST above), never from raw request
// input, so this never resolves outside backend/public/.
function readStaticFile(file) {
  return fs.readFileSync(path.join(PUBLIC_DIR, file));
}

module.exports = { webStatic, readStaticFile, STATIC_HEADERS, CSP, PUBLIC_DIR };
