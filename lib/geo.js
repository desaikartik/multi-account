'use strict';
// Coarse geo resolution (spec §6.5: country/region/city/ASN ONLY — never street
// address or fine coordinates). Injectable via ctx.geo so the suite never hits
// the network; production wires a real provider (MaxMind GeoLite2 local DB or
// ip-api) as the `provider` function.
//
// SAFETY: a lookup must NEVER fail a request — any provider throw/timeout, or a
// private/invalid IP, degrades to null. lat/lon (when a provider supplies them)
// are returned for the transient impossible-travel distance calc ONLY and are
// stripped by coarseGeo() before anything is persisted.

const net = require('net');
const { canonicalizeIp, ipInCidr } = require('./netip');

// Non-public ranges we never bother geolocating (would return null anyway).
const PRIVATE_CIDRS = [
  '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
  '169.254.0.0/16', '100.64.0.0/10', '0.0.0.0/8',
  '::1/128', 'fc00::/7', 'fe80::/10', '::ffff:127.0.0.0/104',
];

function isPrivateIp(ip) {
  const canon = canonicalizeIp(ip);
  if (!canon) return true;
  return PRIVATE_CIDRS.some(c => ipInCidr(canon, c));
}

// Keep only the coarse, persistable fields (drops lat/lon and anything else).
function coarseGeo(g) {
  if (!g) return null;
  return {
    country: g.country == null ? null : String(g.country).toUpperCase(),
    region: g.region == null ? null : g.region,
    city: g.city == null ? null : g.city,
    asn: g.asn == null ? null : g.asn,
  };
}

// Wrap a raw provider(canonIp) → {country,region,city,asn,lat?,lon?} into a
// safe resolver. Timeouts/throws/private IPs → null.
function createGeoResolver(provider, { timeoutMs = 1500 } = {}) {
  return {
    async lookup(ip) {
      const canon = canonicalizeIp(ip);
      if (!canon || net.isIP(canon) === 0 || isPrivateIp(canon)) return null;
      try {
        const r = await withTimeout(provider(canon), timeoutMs);
        return r || null;
      } catch {
        return null; // best-effort; geo never fails the request
      }
    },
  };
}

// A resolver that always returns null — the default until a provider is wired
// at deploy time (Phase 6). Keeps the pipeline working with no geo data.
function createNullGeoResolver() {
  return { async lookup() { return null; } };
}

// --- ip-api.com HTTP provider -----------------------------------------------
//
// provider(canonIp) → {country,region,city,asn,lat?,lon?} | null. GETs
// `${url}/${canonIp}` via an injected `fetch` (Fetch API shape: resolves to a
// Response-like object with an async .json()). Maps ip-api.com/json/<ip>
// fields: countryCode→country, regionName→region, city→city, as→asn (also
// captures lat/lon for the transient impossible-travel calc). Returns null on
// a non-'success' status or ANY throw (bad JSON, network error, etc.) — the
// wrapping createGeoResolver() would swallow a throw anyway, but this keeps
// the provider's own contract explicit and independently testable. The
// wrapper already filters private/invalid IPs before calling us, so canonIp
// here is always a canonical public IP.
function createIpApiProvider({ fetch, url = 'http://ip-api.com/json' } = {}) {
  return async function ipApiProvider(canonIp) {
    try {
      const res = await fetch(`${url}/${canonIp}`);
      const data = await res.json();
      if (!data || data.status !== 'success') return null;
      return {
        country: data.countryCode == null ? null : data.countryCode,
        region: data.regionName == null ? null : data.regionName,
        city: data.city == null ? null : data.city,
        asn: data.as == null ? null : data.as,
        lat: data.lat,
        lon: data.lon,
      };
    } catch {
      return null;
    }
  };
}

// --- MaxMind GeoLite2 local-DB provider -------------------------------------
//
// provider(canonIp) → {country,region,city,asn,lat?,lon?} | null, reading a
// local MaxMind DB. NO hard dependency on any MaxMind library: the actual
// reader is constructed by an INJECTED `readerFactory(dbPath)` (e.g. the
// `maxmind`/`@maxmind/geoip2-node` reader-open function, wired in by whoever
// deploys with a real .mmdb file). `readerFactory` is called eagerly, ONCE,
// here — so a missing/broken reader throws synchronously out of THIS call
// (never deferred to the first lookup), letting resolveGeoProvider() catch it
// and fall back to a null resolver with a logged warning instead of ever
// crashing module load or a live lookup.
//
// Expected reader shape: reader.city(ip) → (sync or async)
//   { country: {isoCode}, subdivisions: [{isoCode}], city: {names:{en}},
//     traits: {autonomousSystemNumber}, location: {latitude, longitude} }
// (the shape used by `@maxmind/geoip2-node` / `maxmind`'s City reader).
function createGeoLite2Provider({ readerFactory, dbPath } = {}) {
  if (typeof readerFactory !== 'function') {
    throw new Error('createGeoLite2Provider requires a readerFactory(dbPath) function (no MaxMind lib is bundled).');
  }
  const reader = readerFactory(dbPath); // may throw — caller decides the fallback
  return async function geoLite2Provider(canonIp) {
    try {
      const rec = await reader.city(canonIp);
      if (!rec) return null;
      return {
        country: rec.country && rec.country.isoCode ? rec.country.isoCode : null,
        region: rec.subdivisions && rec.subdivisions[0] && rec.subdivisions[0].isoCode
          ? rec.subdivisions[0].isoCode : null,
        city: rec.city && rec.city.names ? rec.city.names.en : null,
        asn: rec.traits && rec.traits.autonomousSystemNumber != null
          ? `AS${rec.traits.autonomousSystemNumber}` : null,
        lat: rec.location ? rec.location.latitude : undefined,
        lon: rec.location ? rec.location.longitude : undefined,
      };
    } catch {
      return null;
    }
  };
}

// --- provider selection ------------------------------------------------------
//
// resolveGeoProvider(config, {fetch, log, readerFactory}) — chooses the real
// resolver wired at deploy time, per config.geoProvider:
//   'ip-api'   → createGeoResolver(createIpApiProvider({fetch, url: config.geoApiUrl}))
//   'geolite2' → createGeoResolver(createGeoLite2Provider({readerFactory, dbPath: config.geolite2DbPath}))
//                (falls back to a null resolver + log.warn if readerFactory is
//                 missing or throws while opening the DB)
//   unset/'none' (default) → createNullGeoResolver(), explicitly logged so the
//                 fail-closed consequence (any geo-fenced user is locked out
//                 of every authenticated route) is visible in the server log.
function resolveGeoProvider(config, { fetch, log, readerFactory } = {}) {
  const logger = log || console;
  const provider = ((config && config.geoProvider) || 'none').toLowerCase();

  if (provider === 'ip-api') {
    // GEO-2 (red-team, Minor): ip-api's free tier is HTTP-only (HTTPS needs a
    // paid key, so config.js does NOT default GEO_API_URL to https — that
    // would silently break the free tier). That means the geo-fence country
    // is fetched over PLAINTEXT HTTP and is MITM-forgeable in transit. This is
    // defense-in-depth + honesty only (no behavior/default change): surface
    // the risk in the server log at wiring time so an operator relying on the
    // fence for anything security-relevant knows to switch providers.
    logger.warn && logger.warn(
      'GEO_PROVIDER=ip-api resolves the geo-fence country over PLAINTEXT HTTP '
      + "(ip-api's free tier has no HTTPS option) — the result is MITM-forgeable "
      + 'in transit. For any deployment where the geo-fence is security-relevant, '
      + 'use GEO_PROVIDER=geolite2 (local MaxMind DB, no network hop) instead.'
    );
    // T2 parity: the geolite2 branch below already warns when its dependency
    // (readerFactory) is missing/broken; this branch had no equivalent warning
    // when `fetch` is missing, silently leaving every lookup as a swallowed
    // null forever. Warn here too, for the same operator visibility.
    if (!fetch) {
      logger.warn && logger.warn(
        'GEO_PROVIDER=ip-api has no fetch implementation available; geo lookups '
        + 'will always resolve to null. Any user with a geoFence configured will '
        + 'be locked out of every authenticated route until this is fixed.'
      );
    }
    return createGeoResolver(createIpApiProvider({ fetch, url: config.geoApiUrl }));
  }

  if (provider === 'geolite2') {
    try {
      return createGeoResolver(createGeoLite2Provider({ readerFactory, dbPath: config.geolite2DbPath }));
    } catch (err) {
      logger.warn && logger.warn(
        `GEO_PROVIDER=geolite2 could not be initialized (${err && err.message}); `
        + 'falling back to no geo resolution. Any user with a geoFence configured '
        + 'will be locked out of authenticated routes until this is fixed.'
      );
      return createNullGeoResolver();
    }
  }

  logger.info && logger.info(
    'GEO_PROVIDER is unset/"none": geo resolution is disabled. Any user with a '
    + 'geoFence configured will be locked out of every authenticated route '
    + '(fail-closed) until a real provider is configured.'
  );
  return createNullGeoResolver();
}

function withTimeout(promise, ms) {
  if (!ms || ms <= 0) return Promise.resolve(promise);
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('geo lookup timeout')), ms);
    Promise.resolve(promise).then(
      v => { clearTimeout(t); resolve(v); },
      e => { clearTimeout(t); reject(e); },
    );
  });
}

// Great-circle distance in km between two {lat,lon} fixes. Used only by the
// impossible-travel rule; requires true coordinates (never country centroids).
function haversineKm(a, b) {
  if (!a || !b || a.lat == null || a.lon == null || b.lat == null || b.lon == null) return null;
  const R = 6371;
  const toRad = d => (d * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const s = Math.sin(dLat / 2) ** 2
    + Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
}

module.exports = {
  createGeoResolver, createNullGeoResolver, coarseGeo, isPrivateIp, haversineKm,
  createIpApiProvider, createGeoLite2Provider, resolveGeoProvider,
};
