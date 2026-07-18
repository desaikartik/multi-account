'use strict';
// Device presence + device/travel anomaly evaluation (spec §6.6).
//
// recordPresence() runs after a successful auth event (login / refresh / command
// poll). It updates the device doc in place (the storage-lean heartbeat that
// dead-man is measured from) and evaluates:
//   - new/unknown device  — first sighting of a deviceId for an ESTABLISHED user
//     (a user's very first device is NOT anomalous; nothing to compare).
//   - impossible travel    — the SAME device reporting from two far-apart fixes
//     in a short window (per-device comparison naturally excludes the multi-
//     device-at-different-sites false positive the review flagged).
//
// COORDINATE HANDLING: audit/report geo stays COARSE (country/region/city/asn).
// The transient previous fix (lat/lon/asn/at) is kept in device.lastFix ONLY to
// power the haversine travel calc — it is never written to an audit event and
// never surfaced in coarse reports. Documented tradeoff (see handoff).
//
// FAIL-OPEN: recordPresence never throws into the auth path — a logging/geo/DB
// hiccup must not break a legitimate login.

const netip = require('./netip');
const anomaly = require('./anomaly');
const { coarseGeo } = require('./geo');
const geoLib = require('./geo');
const { redactSensitive } = require('./errors');

// Pure travel assessment: is moving from prevFix → curFix physically implausible?
// Returns { impossible, speedKmh, reason }. Requires TRUE lat/lon on both fixes
// (coarse country centroids are never enough → never emits on country-only).
function assessTravel(prevFix, curFix, cfg) {
  if (!prevFix || !curFix) return { impossible: false };
  if (prevFix.lat == null || prevFix.lon == null || curFix.lat == null || curFix.lon == null) {
    return { impossible: false, reason: 'no_coordinates' };
  }
  const elapsedMs = new Date(curFix.at).getTime() - new Date(prevFix.at).getTime();
  if (elapsedMs <= 0) return { impossible: false, reason: 'non_positive_elapsed' };
  if (elapsedMs < cfg.minTravelMinutes * 60 * 1000) return { impossible: false, reason: 'too_soon' };
  if (elapsedMs > cfg.impossibleTravelWindowMs) return { impossible: false, reason: 'outside_window' };
  // VPN/carrier NAT: two IPs on the same ASN are almost always one person, not
  // teleportation — skip to avoid the biggest false-positive source.
  if (prevFix.asn && curFix.asn && prevFix.asn === curFix.asn) return { impossible: false, reason: 'same_asn' };
  // Coarse geo places mobile/CGNAT IPs at the carrier's gateway city, so ONE
  // stationary device switching Wi-Fi↔cellular (different ASN, same country)
  // computes an implausible intra-country speed. Only flag CRITICAL impossible
  // travel when the COUNTRY actually changes and both countries are known —
  // cross-border teleportation is the high-value, low-false-positive signal.
  // (Documented residual: same-country teleportation is not flagged.)
  if (!prevFix.country || !curFix.country || prevFix.country === curFix.country) {
    return { impossible: false, reason: 'same_or_unknown_country' };
  }
  const km = geoLib.haversineKm(prevFix, curFix);
  if (km == null || km < cfg.minTravelKm) return { impossible: false, reason: 'too_close', km };
  const speedKmh = km / (elapsedMs / 3_600_000);
  return { impossible: speedKmh > cfg.impossibleTravelKmh, speedKmh, km };
}

async function recordPresence(ctx, { user, deviceId, ip }) {
  try {
    if (!deviceId) return;
    const now = ctx.clock.now();
    const cfg = ctx.config.anomaly;
    const fullGeo = await safeGeo(ctx, ip); // full geo incl. transient lat/lon
    const device = await ctx.repo.devices.findById(deviceId);

    // --- deviceId ownership conflict ---
    // deviceId is client-supplied. If a device record already exists under a
    // DIFFERENT user, a second user is (accidentally or maliciously) reusing that
    // id. Do NOT overwrite the owner's record (that would let an attacker corrupt
    // another user's device state / last-fix and evaluate travel across users).
    // Refuse the takeover and log it — clients must mint a unique deviceId.
    if (device && device.userId && device.userId !== user._id) {
      await anomaly.emit(ctx, {
        severity: 'warn', userId: user._id, deviceId, ip,
        reason: anomaly.REASONS.DEVICE_OWNERSHIP_CONFLICT,
        detail: 'deviceId already registered to another user',
        dedupeKey: `anomaly:device_ownership_conflict:${deviceId}:${user._id}`,
      });
      return;
    }

    // --- new/unknown device (check BEFORE upsert) ---
    if (!device) {
      const prior = await ctx.repo.devices.find({ userId: user._id });
      const isFirstEver = prior.length === 0;
      if (!isFirstEver && cfg.newDeviceIsAnomaly) {
        await anomaly.emit(ctx, {
          severity: 'warn', userId: user._id, deviceId, ip, reason: anomaly.REASONS.NEW_DEVICE,
          detail: `new device ${deviceId} on an established account`,
          dedupeKey: `anomaly:new_device:${deviceId}`,
        });
      }
    }

    // --- impossible travel (same device, prior fix vs current fix) ---
    const curFix = fullGeo && fullGeo.lat != null
      ? {
        lat: fullGeo.lat, lon: fullGeo.lon, asn: fullGeo.asn || null,
        country: fullGeo.country ? String(fullGeo.country).toUpperCase() : null, at: now,
      }
      : null;
    if (device && device.lastFix && curFix) {
      const verdict = assessTravel(device.lastFix, curFix, cfg);
      if (verdict.impossible) {
        const dayBucket = Math.floor(now.getTime() / (24 * 60 * 60 * 1000));
        await anomaly.emit(ctx, {
          severity: 'critical', userId: user._id, deviceId, ip, reason: anomaly.REASONS.IMPOSSIBLE_TRAVEL,
          detail: `~${Math.round(verdict.speedKmh)} km/h between fixes`,
          dedupeKey: `anomaly:impossible_travel:${user._id}:${dayBucket}`,
        });
      }
    }

    // --- upsert the device (after evaluation) ---
    const { ipEnc, ipIdx } = netip.encryptIp(ctx, ip, `device:${deviceId}`);
    const patch = {
      userId: user._id, lastSeen: now, monitoringLastAt: now,
      lastIpEnc: ipEnc, lastIpIdx: ipIdx, lastGeo: coarseGeo(fullGeo),
      lastFix: curFix, // transient coordinate for the next travel calc (not coarse geo, not audited)
    };
    if (device) await ctx.repo.devices.updateById(deviceId, patch);
    else await ctx.repo.devices.insert({ _id: deviceId, firstSeen: now, status: 'active', ...patch });
  } catch (err) {
    if (ctx.logger && ctx.logger.error) ctx.logger.error(redactSensitive('recordPresence failed: ' + (err && err.message)));
  }
}

// Client heartbeat ingestion (the telemetry engine's report). The client
// (Monitoring Service) collects its OWN public IPv4 + IPv6 + coarse geo and
// sends them here; the backend saves them on the device record (updated in
// place — NO per-beat audit row, per the 512MB budget) and CROSS-CHECKS the
// report against the IP it actually observed on the connection. Client-reported
// data is trusted to the degree the managed endpoint is; the cross-check
// catches spoof/proxy. Reuses the same anomaly rules as recordPresence.
//
// report = { ipv4, ipv6, geo4, geo6, appVersion, os }
//   geoN = { country, region, city, asn, lat?, lon? } | null  (lat/lon transient)
async function recordHeartbeat(ctx, { user, deviceId, observedIp, report }) {
  if (!deviceId) throw httpError(400, 'Missing device id.');
  const now = ctx.clock.now();
  const cfg = ctx.config.anomaly;
  const device = await ctx.repo.devices.findById(deviceId);

  // deviceId ownership conflict — do NOT overwrite another user's device.
  if (device && device.userId && device.userId !== user._id) {
    await anomaly.emit(ctx, {
      severity: 'warn', userId: user._id, deviceId, ip: observedIp,
      reason: anomaly.REASONS.DEVICE_OWNERSHIP_CONFLICT,
      detail: 'deviceId already registered to another user',
      dedupeKey: `anomaly:device_ownership_conflict:${deviceId}:${user._id}`,
    });
    return { conflict: true };
  }

  const r = report || {};
  const ipv4 = netip.canonicalizeIp(r.ipv4);
  const ipv6 = netip.canonicalizeIp(r.ipv6);
  const reported = [ipv4, ipv6].filter(Boolean);
  const observed = netip.canonicalizeIp(observedIp);

  // CROSS-CHECK: the IP the backend actually saw must be one the client claims.
  // A mismatch means the client is behind a proxy/VPN it did not report, or is
  // spoofing — a deduped anomaly, not a hard failure.
  if (observed && reported.length && !reported.includes(observed)) {
    await anomaly.emit(ctx, {
      severity: 'warn', userId: user._id, deviceId, ip: observedIp,
      reason: anomaly.REASONS.IP_MISMATCH,
      detail: `observed ${observed} not among reported [${reported.join(', ')}]`,
      dedupeKey: `anomaly:ip_mismatch:${deviceId}:${observed}:${Math.floor(now.getTime() / (60 * 60 * 1000))}`,
    });
  }

  // new/unknown device (first-ever suppressed) — check BEFORE upsert.
  if (!device) {
    const prior = await ctx.repo.devices.find({ userId: user._id });
    if (prior.length > 0 && cfg.newDeviceIsAnomaly) {
      await anomaly.emit(ctx, {
        severity: 'warn', userId: user._id, deviceId, ip: observedIp, reason: anomaly.REASONS.NEW_DEVICE,
        detail: `new device ${deviceId} on an established account`,
        dedupeKey: `anomaly:new_device:${deviceId}`,
      });
    }
  }

  // impossible travel off the CLIENT-reported geo (prefer the v4 fix).
  const curFix = fixFrom(r.geo4, now) || fixFrom(r.geo6, now);
  if (device && device.lastFix && curFix) {
    const verdict = assessTravel(device.lastFix, curFix, cfg);
    if (verdict.impossible) {
      const dayBucket = Math.floor(now.getTime() / (24 * 60 * 60 * 1000));
      await anomaly.emit(ctx, {
        severity: 'critical', userId: user._id, deviceId, ip: observedIp, reason: anomaly.REASONS.IMPOSSIBLE_TRAVEL,
        detail: `~${Math.round(verdict.speedKmh)} km/h between fixes`,
        dedupeKey: `anomaly:impossible_travel:${user._id}:${dayBucket}`,
      });
    }
  }

  // Upsert the device in place — store BOTH public IPs (encrypted, record-bound)
  // + coarse geo. NO audit row for a routine beat.
  const enc4 = ipv4 ? netip.encryptIp(ctx, ipv4, `device:${deviceId}`) : { ipEnc: null, ipIdx: null };
  const enc6 = ipv6 ? netip.encryptIp(ctx, ipv6, `device:${deviceId}`) : { ipEnc: null, ipIdx: null };
  const patch = {
    userId: user._id, lastSeen: now, monitoringLastAt: now,
    appVersion: r.appVersion || (device && device.appVersion) || null,
    os: r.os || (device && device.os) || null,
    lastIpv4Enc: enc4.ipEnc, lastIpv4Idx: enc4.ipIdx, lastGeo4: coarseGeo(r.geo4),
    lastIpv6Enc: enc6.ipEnc, lastIpv6Idx: enc6.ipIdx, lastGeo6: coarseGeo(r.geo6),
    // Primary (v4 preferred) mirrors the single lastIp* fields the reporting/
    // dead-man code already reads.
    lastIpEnc: enc4.ipEnc || enc6.ipEnc, lastIpIdx: enc4.ipIdx || enc6.ipIdx,
    lastGeo: coarseGeo(r.geo4) || coarseGeo(r.geo6),
    lastFix: curFix,
  };
  if (device) await ctx.repo.devices.updateById(deviceId, patch);
  else await ctx.repo.devices.insert({ _id: deviceId, firstSeen: now, status: 'active', ...patch });
  return { conflict: false };
}

// Build a transient {lat,lon,asn,country,at} fix from a reported coarse-geo
// object (lat/lon used only for the travel calc; never persisted as coarse geo).
function fixFrom(geo, now) {
  if (!geo || geo.lat == null || geo.lon == null) return null;
  return {
    lat: geo.lat, lon: geo.lon, asn: geo.asn || null,
    country: geo.country ? String(geo.country).toUpperCase() : null, at: now,
  };
}

// Dead-man scan (run by the scheduler / reporting): devices holding creds that
// have gone silent beyond deadManDays. Excludes terminal-state devices
// (wiped/locked/deprovisioned) — those are SUPPOSED to be silent — and emits at
// most once per silence episode (dedupe key includes the lastSeen day).
async function deadManScan(ctx) {
  const now = ctx.clock.now();
  const cutoffMs = now.getTime() - ctx.config.anomaly.deadManDays * 24 * 60 * 60 * 1000;
  const devices = await ctx.repo.devices.find({});
  let fired = 0;
  for (const d of devices) {
    if (d.status && d.status !== 'active') continue;
    const last = d.lastSeen ? new Date(d.lastSeen).getTime() : (d.firstSeen ? new Date(d.firstSeen).getTime() : 0);
    if (last && last < cutoffMs) {
      const episode = Math.floor(last / (24 * 60 * 60 * 1000)); // re-arms once the device heartbeats again
      await anomaly.emit(ctx, {
        severity: 'warn', userId: d.userId, deviceId: d._id, reason: anomaly.REASONS.DEAD_MAN,
        detail: `silent since ${new Date(last).toISOString()}`,
        dedupeKey: `anomaly:dead_man:${d._id}:${episode}`,
      });
      fired++;
    }
  }
  return { scanned: devices.length, fired };
}

async function safeGeo(ctx, ip) {
  try {
    return ctx.geo && typeof ctx.geo.lookup === 'function' ? await ctx.geo.lookup(ip) : null;
  } catch {
    return null;
  }
}

module.exports = { recordPresence, recordHeartbeat, assessTravel, deadManScan };
