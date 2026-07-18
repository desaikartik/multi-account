'use strict';
// Production MX resolver. Injected into ctx as `resolveMx` so signup can be
// tested offline. Kept in its own module so server.js wires the real one and
// tests never touch the network.

const dns = require('dns').promises;

// Resolve MX records for a domain. Returns [] when the domain has none.
async function resolveMx(domain) {
  return dns.resolveMx(String(domain));
}

// Resolve A/AAAA records (implicit-MX fallback: a domain with only an address
// record still receives mail per RFC 5321 §5.1). Returns [] when it has none.
async function resolveHost(domain) {
  const d = String(domain);
  const [a, aaaa] = await Promise.all([
    dns.resolve4(d).catch(() => []),
    dns.resolve6(d).catch(() => []),
  ]);
  return [...a, ...aaaa];
}

module.exports = { resolveMx, resolveHost };
