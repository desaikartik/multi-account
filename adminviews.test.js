'use strict';
// Task 6 (Phase 5) — shared admin view-model unit tests.
//
// adminviews.js is pure data -> view-model functions (no DOM, no fetch, no
// window): it is byte-identical to desktop/src/renderer/adminviews.js later
// (Task 9 parity test), so nothing in here may depend on a browser or Node
// runtime feature beyond Intl (full ICU) and JSON.
//
// Run: cd backend && node --test

const { test } = require('node:test');
const assert = require('node:assert/strict');

const AdminViews = require('./public/adminviews.js');
const {
  esc, escAttr, formatTs, formatRelative, formatGeo,
  overviewModel, timelineRows, deviceRows, ipGeoRows, alertRows,
  traceModel, transferRows, verifyModel, userRows, usageOverviewRows,
  userDeviceRows, toCsv, csvColumns, effectivePolicyModel,
} = AdminViews;

// ===========================================================================
// esc / escAttr — pure string escaping, no DOM
// ===========================================================================

test('esc: escapes the five HTML-special characters', () => {
  assert.equal(esc('<script>alert("x")</script>'), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
  assert.equal(esc(`it's "quoted" <b>&amp;</b>`), 'it&#39;s &quot;quoted&quot; &lt;b&gt;&amp;amp;&lt;/b&gt;');
});

test('esc: null/undefined become empty string; numbers/booleans stringify', () => {
  assert.equal(esc(null), '');
  assert.equal(esc(undefined), '');
  assert.equal(esc(0), '0');
  assert.equal(esc(42), '42');
  assert.equal(esc(false), 'false');
});

test('escAttr: also neutralizes quotes for safe use inside an HTML attribute', () => {
  const payload = `x" onmouseover="alert(1)`;
  const out = escAttr(payload);
  assert.ok(!out.includes('"'));
  assert.equal(out, 'x&quot; onmouseover=&quot;alert(1)');
  assert.equal(escAttr('<script>'), '&lt;script&gt;');
});

// ===========================================================================
// formatTs — Intl.DateTimeFormat, explicit IANA zone, 'YYYY-MM-DD HH:mm:ss'
// ===========================================================================

test('formatTs: Asia/Kolkata (UTC+05:30) against a fixed winter instant', () => {
  assert.equal(formatTs('2026-01-15T10:00:00.000Z', 'Asia/Kolkata'), '2026-01-15 15:30:00');
});

test('formatTs: America/New_York EST (winter, UTC-5, no DST) against a fixed instant', () => {
  assert.equal(formatTs('2026-01-15T10:00:00.000Z', 'America/New_York'), '2026-01-15 05:00:00');
});

test('formatTs: America/New_York EDT (summer, UTC-4, DST) against a fixed instant', () => {
  assert.equal(formatTs('2026-07-16T14:05:33.000Z', 'America/New_York'), '2026-07-16 10:05:33');
});

test('formatTs: Asia/Kolkata against the same summer instant (half-hour offset, no DST)', () => {
  assert.equal(formatTs('2026-07-16T14:05:33.000Z', 'Asia/Kolkata'), '2026-07-16 19:35:33');
});

test('formatTs: 24-hour clock never rolls midnight to "24:00:00"', () => {
  assert.equal(formatTs('2026-01-01T18:30:00.000Z', 'Asia/Kolkata'), '2026-01-02 00:00:00');
});

test('formatTs: missing/invalid iso renders as an em dash', () => {
  assert.equal(formatTs(null, 'Asia/Kolkata'), '—');
  assert.equal(formatTs(undefined, 'Asia/Kolkata'), '—');
  assert.equal(formatTs('not-a-date', 'Asia/Kolkata'), '—');
  assert.equal(formatTs('', 'Asia/Kolkata'), '—');
});

test('formatTs: undefined timeZone falls back to the viewer (host) local zone', () => {
  const hostTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const iso = '2026-03-05T12:00:00.000Z';
  assert.equal(formatTs(iso), formatTs(iso, hostTz));
});

// ===========================================================================
// formatRelative — coarse "Xm/h/d ago" buckets
// ===========================================================================

test('formatRelative: buckets from just-now through days', () => {
  const nowMs = 1_700_000_000_000;
  const iso = (deltaMs) => new Date(nowMs - deltaMs).toISOString();
  assert.equal(formatRelative(iso(0), nowMs), 'just now');
  assert.equal(formatRelative(iso(30_000), nowMs), 'just now');
  assert.equal(formatRelative(iso(3 * 60_000), nowMs), '3m ago');
  assert.equal(formatRelative(iso(59 * 60_000), nowMs), '59m ago');
  assert.equal(formatRelative(iso(2 * 3600_000), nowMs), '2h ago');
  assert.equal(formatRelative(iso(23 * 3600_000), nowMs), '23h ago');
  assert.equal(formatRelative(iso(5 * 86400_000), nowMs), '5d ago');
});

test('formatRelative: missing/invalid iso renders as an em dash', () => {
  assert.equal(formatRelative(null, 1_700_000_000_000), '—');
  assert.equal(formatRelative('not-a-date', 1_700_000_000_000), '—');
});

test('formatRelative: a future timestamp (clock skew) never goes negative — clamps to "just now"', () => {
  const nowMs = 1_700_000_000_000;
  assert.equal(formatRelative(new Date(nowMs + 5000).toISOString(), nowMs), 'just now');
});

// ===========================================================================
// formatGeo — "City, Region, CC" with graceful degradation
// ===========================================================================

test('formatGeo: renders city, region, country when all present', () => {
  assert.equal(formatGeo({ country: 'US', region: 'CA', city: 'San Francisco', asn: 'AS123' }), 'San Francisco, CA, US');
});

test('formatGeo: null geo and empty geo both render as an em dash', () => {
  assert.equal(formatGeo(null), '—');
  assert.equal(formatGeo({ country: null, region: null, city: null, asn: null }), '—');
});

test('formatGeo: partial geo omits the missing pieces', () => {
  assert.equal(formatGeo({ country: 'US', region: null, city: null, asn: null }), 'US');
  assert.equal(formatGeo({ country: null, region: null, city: 'Nowhere', asn: null }), 'Nowhere');
});

test('formatGeo: escapes injected HTML in city/region', () => {
  assert.equal(
    formatGeo({ country: 'US', region: '<script>', city: 'X', asn: null }),
    'X, &lt;script&gt;, US',
  );
});

// ===========================================================================
// overviewModel({devices, storage, timeline, nowMs})
// ===========================================================================

test('overviewModel: distinct non-null userIds in-window + devices seen within 24h + storage passthrough', () => {
  const nowMs = 1_700_000_000_000;
  const devices = [
    { deviceId: 'd1', userId: 'u1', lastSeen: new Date(nowMs - 2 * 3600_000).toISOString() }, // active
    { deviceId: 'd2', userId: 'u2', lastSeen: new Date(nowMs - 30 * 3600_000).toISOString() }, // stale
    { deviceId: 'd3', userId: 'u3', lastSeen: null }, // never seen
  ];
  const timeline = {
    windowDays: 7,
    events: [
      { userId: 'u1' }, { userId: 'u2' }, { userId: 'u1' }, { userId: null }, { userId: 'u1' },
    ],
  };
  const storage = { estimatedBytes: 1000, capacityBytes: 2000, percent: 50 };
  const model = overviewModel({ devices, storage, timeline, nowMs });
  assert.equal(model.activeUsers, 2);
  assert.equal(model.activeDevices, 1);
  assert.equal(model.totalDevices, 3);
  assert.equal(model.windowDays, 7);
  assert.equal(model.storagePercent, 50);
  assert.equal(model.storageEstimatedBytes, 1000);
  assert.equal(model.storageCapacityBytes, 2000);
});

test('overviewModel: a device seen exactly 24h ago still counts as active (inclusive boundary)', () => {
  const nowMs = 1_700_000_000_000;
  const devices = [{ deviceId: 'd1', userId: 'u1', lastSeen: new Date(nowMs - 24 * 3600_000).toISOString() }];
  const model = overviewModel({ devices, storage: {}, timeline: { events: [] }, nowMs });
  assert.equal(model.activeDevices, 1);
});

test('overviewModel: empty inputs never throw and yield zeros', () => {
  const model = overviewModel({ devices: [], storage: {}, timeline: { events: [] }, nowMs: 1_700_000_000_000 });
  assert.equal(model.activeUsers, 0);
  assert.equal(model.activeDevices, 0);
  assert.equal(model.totalDevices, 0);
});

test('overviewModel: a userId shaped like an Object.prototype key ("__proto__") is still counted correctly', () => {
  const timeline = {
    events: [
      { userId: '__proto__' }, { userId: 'toString' }, { userId: 'constructor' },
      { userId: '__proto__' }, // repeat must not double-count
    ],
  };
  const model = overviewModel({ devices: [], storage: {}, timeline, nowMs: 1_700_000_000_000 });
  assert.equal(model.activeUsers, 3);
});

// ===========================================================================
// timelineRows(events, tz)
// ===========================================================================

test('timelineRows: maps every documented field and formats geo/time', () => {
  const events = [{
    seq: 1, serverTs: '2026-07-16T14:05:33.000Z', eventType: 'login', severity: 'info',
    userId: 'u1', email: 'u1@x.com', deviceId: 'dev1', result: 'ok', reason: null, watermarkId: null,
    geo: { country: 'US', region: 'CA', city: 'San Francisco', asn: 'AS123' }, ip: '1.2.3.4',
  }];
  const rows = timelineRows(events, 'Asia/Kolkata');
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0], {
    seq: 1,
    time: '2026-07-16 19:35:33',
    eventType: 'login',
    severity: 'info',
    userId: 'u1',
    email: 'u1@x.com',
    deviceId: 'dev1',
    result: 'ok',
    reason: '—',
    geo: 'San Francisco, CA, US',
    ip: '1.2.3.4',
  });
});

test('timelineRows: absent optional fields render as an em dash, geo null renders as an em dash', () => {
  const events = [{ seq: 2, serverTs: '2026-07-16T14:05:33.000Z', eventType: 'anomaly', severity: 'critical', userId: null, deviceId: null, result: null, reason: null, watermarkId: null, geo: null, ip: null }];
  const rows = timelineRows(events, 'UTC');
  assert.equal(rows[0].userId, '—');
  assert.equal(rows[0].email, '—');
  assert.equal(rows[0].deviceId, '—');
  assert.equal(rows[0].result, '—');
  assert.equal(rows[0].reason, '—');
  assert.equal(rows[0].geo, '—');
  assert.equal(rows[0].ip, '—');
});

test('timelineRows: a <script> reason renders inert (escaped)', () => {
  const events = [{ seq: 3, serverTs: '2026-07-16T14:05:33.000Z', eventType: 'anomaly', severity: 'critical', userId: 'u1', deviceId: 'd1', result: null, reason: '<script>alert(1)</script>', watermarkId: null, geo: null, ip: null }];
  const rows = timelineRows(events, 'UTC');
  assert.ok(!rows[0].reason.includes('<script>'));
  assert.equal(rows[0].reason, '&lt;script&gt;alert(1)&lt;/script&gt;');
});

test('timelineRows: empty array yields empty array', () => {
  assert.deepEqual(timelineRows([], 'UTC'), []);
  assert.deepEqual(timelineRows(undefined, 'UTC'), []);
});

// ===========================================================================
// deviceRows(devices, tz) — IPv4 + IPv6 + geo columns
// ===========================================================================

test('deviceRows: maps every documented field including both IP families', () => {
  const devices = [{
    deviceId: 'dev1', userId: 'u1', email: 'u1@x.com', status: 'active',
    firstSeen: '2026-07-01T00:00:00.000Z', lastSeen: '2026-07-16T14:05:33.000Z',
    appVersion: '1.2.3', os: 'windows',
    lastIp: '1.2.3.4', geo: { country: 'US', region: 'CA', city: 'SF', asn: null },
    ipv4: '1.2.3.4', geo4: { country: 'US', region: 'CA', city: 'SF', asn: null },
    ipv6: '2001:db8::1', geo6: { country: 'DE', region: null, city: null, asn: null },
  }];
  const rows = deviceRows(devices, 'UTC');
  assert.deepEqual(rows[0], {
    deviceId: 'dev1', userId: 'u1', email: 'u1@x.com', status: 'active',
    firstSeen: '2026-07-01 00:00:00', lastSeen: '2026-07-16 14:05:33',
    appVersion: '1.2.3', os: 'windows',
    ipv4: '1.2.3.4', geo4: 'SF, CA, US',
    ipv6: '2001:db8::1', geo6: 'DE',
    lastIp: '1.2.3.4', geo: 'SF, CA, US',
  });
});

test('deviceRows: missing IP/geo fields degrade to em dashes; a hostile os string is escaped', () => {
  const devices = [{ deviceId: 'dev2', userId: null, status: 'active', firstSeen: null, lastSeen: null, appVersion: null, os: '<img src=x onerror=alert(1)>', lastIp: null, geo: null, ipv4: null, geo4: null, ipv6: null, geo6: null }];
  const rows = deviceRows(devices, 'UTC');
  assert.equal(rows[0].userId, '—');
  assert.equal(rows[0].email, '—');
  assert.equal(rows[0].firstSeen, '—');
  assert.equal(rows[0].ipv4, '—');
  assert.equal(rows[0].geo4, '—');
  assert.ok(!rows[0].os.includes('<img'));
});

// ===========================================================================
// ipGeoRows(devices, tz) — the IP & Geo view (narrower, per-device)
// ===========================================================================

test('ipGeoRows: focuses on deviceId/userId/lastSeen + both IP families', () => {
  const devices = [{
    deviceId: 'dev1', userId: 'u1', email: 'u1@x.com', status: 'active',
    lastSeen: '2026-07-16T14:05:33.000Z', firstSeen: null, appVersion: null, os: null, lastIp: null, geo: null,
    ipv4: '1.2.3.4', geo4: { country: 'US', region: null, city: null, asn: null },
    ipv6: null, geo6: null,
  }];
  const rows = ipGeoRows(devices, 'UTC');
  assert.deepEqual(rows[0], {
    deviceId: 'dev1', userId: 'u1', email: 'u1@x.com', lastSeen: '2026-07-16 14:05:33',
    ipv4: '1.2.3.4', geo4: 'US', ipv6: '—', geo6: '—',
  });
});

test('ipGeoRows: hostile payloads in deviceId/userId/ipv4/ipv6/geo parts all render inert', () => {
  const devices = [{
    deviceId: '<script>d</script>', userId: '<script>u</script>', status: 'active',
    lastSeen: '2026-07-16T14:05:33.000Z', firstSeen: null, appVersion: null, os: null, lastIp: null, geo: null,
    ipv4: '<script>4</script>',
    geo4: { country: '<script>cc</script>', region: '<script>r</script>', city: '<script>c</script>', asn: null },
    ipv6: '<script>6</script>',
    geo6: { country: null, region: null, city: '<img src=x onerror=alert(1)>', asn: null },
  }];
  const rows = ipGeoRows(devices, 'UTC');
  const row = rows[0];
  for (const field of ['deviceId', 'userId', 'ipv4', 'ipv6', 'geo4']) {
    assert.ok(!row[field].includes('<script>'), `${field} must not contain a raw <script> tag`);
  }
  assert.ok(!row.geo6.includes('<img'), 'geo6 must not contain a raw <img> tag');
  assert.equal(row.deviceId, '&lt;script&gt;d&lt;/script&gt;');
  assert.equal(row.userId, '&lt;script&gt;u&lt;/script&gt;');
  assert.equal(row.ipv4, '&lt;script&gt;4&lt;/script&gt;');
  assert.equal(row.ipv6, '&lt;script&gt;6&lt;/script&gt;');
  assert.equal(row.geo4, '&lt;script&gt;c&lt;/script&gt;, &lt;script&gt;r&lt;/script&gt;, &lt;script&gt;cc&lt;/script&gt;');
  assert.equal(row.geo6, '&lt;img src=x onerror=alert(1)&gt;');
});

// ===========================================================================
// alertRows(alerts, tz)
// ===========================================================================

test('alertRows: maps every documented field, including email/reasonLabel/alertsMuted (E3)', () => {
  const alerts = [{
    seq: 9, serverTs: '2026-07-16T14:05:33.000Z', severity: 'critical', eventType: 'anomaly',
    reason: 'cross_user_import', userId: 'u2', deviceId: 'dev2',
    email: 'affected@x.com', reasonLabel: 'A file was imported by a different user than exported it', alertsMuted: false,
  }];
  const rows = alertRows(alerts, 'Asia/Kolkata');
  assert.deepEqual(rows[0], {
    seq: 9, time: '2026-07-16 19:35:33', severity: 'critical', eventType: 'anomaly',
    reason: 'cross_user_import', userId: 'u2', deviceId: 'dev2',
    email: 'affected@x.com', reasonLabel: 'A file was imported by a different user than exported it', alertsMuted: false,
  });
});

test('alertRows: a hostile reason/email/reasonLabel string renders inert', () => {
  const alerts = [{
    seq: 10, serverTs: '2026-07-16T14:05:33.000Z', severity: 'warn', eventType: 'anomaly',
    reason: '<script>bad()</script>', userId: null, deviceId: null,
    email: '<script>e</script>', reasonLabel: '<script>l</script>', alertsMuted: false,
  }];
  const rows = alertRows(alerts, 'UTC');
  assert.ok(!rows[0].reason.includes('<script>'));
  assert.ok(!rows[0].email.includes('<script>'));
  assert.ok(!rows[0].reasonLabel.includes('<script>'));
});

test('alertRows: null email/reasonLabel render as the escOr placeholder, alertsMuted defaults falsy, never throws', () => {
  const alerts = [{ seq: 11, serverTs: '2026-07-16T14:05:33.000Z', severity: 'warn', eventType: 'anomaly', reason: null, userId: null, deviceId: null, email: null, reasonLabel: null }];
  const rows = alertRows(alerts, 'UTC');
  assert.equal(rows[0].email, '—');
  assert.equal(rows[0].reasonLabel, '—');
  assert.equal(rows[0].alertsMuted, false);
});

// ===========================================================================
// traceModel(trace, tz)
// ===========================================================================

test('traceModel: same-user imports are not flagged cross-user', () => {
  const trace = {
    watermarkId: 'wm1',
    export: { userId: 'u1', deviceId: 'd1', exportedAt: '2026-07-01T00:00:00.000Z', fileSha256: 'abc123' },
    imports: [{ userId: 'u1', deviceId: 'd2', at: '2026-07-02T00:00:00.000Z', ip: '9.9.9.9' }],
  };
  const model = traceModel(trace, 'UTC');
  assert.equal(model.watermarkId, 'wm1');
  assert.equal(model.export.userId, 'u1');
  assert.equal(model.export.exportedAt, '2026-07-01 00:00:00');
  assert.equal(model.importCount, 1);
  assert.equal(model.crossUser, false);
  assert.equal(model.imports[0].crossUser, false);
});

test('traceModel: an import by a different user is flagged cross-user at both row and summary level', () => {
  const trace = {
    watermarkId: 'wm2',
    export: { userId: 'u1', deviceId: 'd1', exportedAt: '2026-07-01T00:00:00.000Z', fileSha256: 'abc123' },
    imports: [
      { userId: 'u1', deviceId: 'd2', at: '2026-07-02T00:00:00.000Z', ip: '9.9.9.9' },
      { userId: 'u2', deviceId: 'd3', at: '2026-07-03T00:00:00.000Z', ip: '8.8.8.8' },
    ],
  };
  const model = traceModel(trace, 'UTC');
  assert.equal(model.crossUser, true);
  assert.equal(model.imports[0].crossUser, false);
  assert.equal(model.imports[1].crossUser, true);
});

test('traceModel: no imports yet renders empty list, crossUser false', () => {
  const trace = { watermarkId: 'wm3', export: { userId: 'u1', deviceId: 'd1', exportedAt: '2026-07-01T00:00:00.000Z', fileSha256: 'abc' }, imports: [] };
  const model = traceModel(trace, 'UTC');
  assert.deepEqual(model.imports, []);
  assert.equal(model.crossUser, false);
  assert.equal(model.importCount, 0);
});

test('traceModel: a hostile watermarkId/deviceId/fileSha256 renders inert', () => {
  const trace = {
    watermarkId: '<script>wm</script>',
    export: { userId: 'u1', deviceId: '<script>d</script>', exportedAt: '2026-07-01T00:00:00.000Z', fileSha256: '<script>sha</script>' },
    imports: [],
  };
  const model = traceModel(trace, 'UTC');
  assert.ok(!model.watermarkId.includes('<script>'));
  assert.ok(!model.export.deviceId.includes('<script>'));
  assert.ok(!model.export.fileSha256.includes('<script>'));
  assert.equal(model.export.fileSha256, '&lt;script&gt;sha&lt;/script&gt;');
});

// ===========================================================================
// transferRows(transfers, tz) — cross-user badge (mirrors Task 5's server alert)
// ===========================================================================

test('transferRows: same-user-only transfer has no cross-user flag/badge', () => {
  const transfers = [{
    watermarkId: 'wm1',
    export: { userId: 'u1', deviceId: 'd1', exportedAt: '2026-07-01T00:00:00.000Z', fileSha256: 'abc' },
    imports: [{ userId: 'u1', deviceId: 'd2', at: '2026-07-02T00:00:00.000Z', ip: '1.1.1.1' }],
    importCount: 1,
  }];
  const rows = transferRows(transfers, 'UTC');
  assert.equal(rows[0].crossUser, false);
  assert.equal(rows[0].badge, '');
});

test('transferRows: any importer different from the exporter sets crossUser:true + a "cross-user" badge', () => {
  const transfers = [{
    watermarkId: 'wm2',
    export: { userId: 'u1', deviceId: 'd1', exportedAt: '2026-07-01T00:00:00.000Z', fileSha256: 'abc' },
    imports: [
      { userId: 'u1', deviceId: 'd2', at: '2026-07-02T00:00:00.000Z', ip: '1.1.1.1' },
      { userId: 'u9', deviceId: 'd3', at: '2026-07-03T00:00:00.000Z', ip: '2.2.2.2' },
    ],
    importCount: 2,
  }];
  const rows = transferRows(transfers, 'UTC');
  assert.equal(rows[0].crossUser, true);
  assert.equal(rows[0].badge, 'cross-user');
  assert.equal(rows[0].exportUserId, 'u1');
  assert.equal(rows[0].importCount, 2);
  assert.equal(rows[0].exportedAt, '2026-07-01 00:00:00');
});

test('transferRows: no imports yet is not cross-user', () => {
  const transfers = [{ watermarkId: 'wm3', export: { userId: 'u1', deviceId: 'd1', exportedAt: '2026-07-01T00:00:00.000Z', fileSha256: 'abc' }, imports: [], importCount: 0 }];
  const rows = transferRows(transfers, 'UTC');
  assert.equal(rows[0].crossUser, false);
  assert.equal(rows[0].badge, '');
});

test('transferRows: exposes exporter + importer emails and per-import time / cross-user flag', () => {
  const transfers = [{
    watermarkId: 'wm9',
    export: { userId: 'u1', email: 'boss@x.com', deviceId: 'd1', exportedAt: '2026-07-01T00:00:00.000Z', fileSha256: 'abc' },
    imports: [
      { userId: 'u1', email: 'boss@x.com', deviceId: 'd2', at: '2026-07-02T09:30:00.000Z', ip: '1.1.1.1' },
      { userId: 'u2', email: 'other@x.com', deviceId: 'd3', at: '2026-07-03T10:00:00.000Z', ip: '2.2.2.2' },
    ],
    importCount: 2,
  }];
  const r = transferRows(transfers, 'UTC')[0];
  assert.equal(r.exportEmail, 'boss@x.com');
  assert.equal(r.imports.length, 2);
  assert.equal(r.imports[0].email, 'boss@x.com');
  assert.equal(r.imports[0].crossUser, false);
  assert.equal(r.imports[1].email, 'other@x.com');
  assert.equal(r.imports[1].crossUser, true, 'an importer different from the exporter is flagged cross-user');
  assert.equal(r.imports[1].at, '2026-07-03 10:00:00');
  assert.equal(r.imports[1].ip, '2.2.2.2');
  assert.equal(r.crossUser, true);
});

test('transferRows: null exporter/importer emails degrade to an em dash', () => {
  const rows = transferRows([{
    export: { userId: 'u1', email: null, exportedAt: '2026-07-01T00:00:00.000Z' },
    imports: [{ userId: 'u2', email: null, at: '2026-07-02T00:00:00.000Z' }],
  }], 'UTC');
  assert.equal(rows[0].exportEmail, '—');
  assert.equal(rows[0].imports[0].email, '—');
});

test('transferRows: empty array yields empty array', () => {
  assert.deepEqual(transferRows([], 'UTC'), []);
});

test('transferRows: hostile payloads in watermarkId/exportUserId/exportDeviceId/fileSha256 render inert', () => {
  const transfers = [{
    watermarkId: '<script>wm</script>',
    export: {
      userId: '<script>u</script>', deviceId: '<script>d</script>',
      exportedAt: '2026-07-01T00:00:00.000Z', fileSha256: '<script>sha</script>',
    },
    imports: [],
    importCount: 0,
  }];
  const rows = transferRows(transfers, 'UTC');
  const row = rows[0];
  for (const field of ['watermarkId', 'exportUserId', 'exportDeviceId', 'fileSha256']) {
    assert.ok(!row[field].includes('<script>'), `${field} must not contain a raw <script> tag`);
  }
  assert.equal(row.watermarkId, '&lt;script&gt;wm&lt;/script&gt;');
  assert.equal(row.exportUserId, '&lt;script&gt;u&lt;/script&gt;');
  assert.equal(row.exportDeviceId, '&lt;script&gt;d&lt;/script&gt;');
  assert.equal(row.fileSha256, '&lt;script&gt;sha&lt;/script&gt;');
});

// ===========================================================================
// userRows(users, tz) — GET /admin/reports/users .users
// ===========================================================================

test('userRows: maps every documented field for a healthy user', () => {
  const users = [{
    userId: 'u1', email: 'a@x.com', role: 'member', status: 'active',
    emailVerified: true, importEnabled: true, exportEnabled: false, monitoringEnabled: true,
    entitlementExpiresAt: null, entitlementExpired: false, geoFenceCountries: [],
    noticeAcceptedAt: '2026-01-01T00:00:00.000Z', createdAt: '2026-01-01T00:00:00.000Z',
    createdByEmail: 'boss@x.com',
    deviceCount: 2, lastSeen: '2026-07-16T14:05:33.000Z', openAlerts: 0, issues: [],
  }];
  const rows = userRows(users, 'UTC');
  assert.deepEqual(rows[0], {
    userId: 'u1', email: 'a@x.com', role: 'member', status: 'active',
    importEnabled: 'Yes', exportEnabled: 'No', monitoring: 'On',
    expires: '—', devices: '2', alerts: '0', issues: '—', hasIssues: false,
    createdByEmail: 'boss@x.com', awaitingFirstSignIn: false,
    statusAction: 'suspend', statusActionLabel: 'Suspend',
    pendingApproval: false, rejected: false,
  });
});

test('userRows: a pending self-signup is flagged for approval (Approve/Reject)', () => {
  const rows = userRows([{ userId: 'p1', email: 'pend@x.com', role: 'member', status: 'pending', deviceCount: 0, openAlerts: 0, issues: ['Awaiting approval'] }], 'UTC');
  assert.equal(rows[0].pendingApproval, true);
  assert.equal(rows[0].rejected, false);
  assert.equal(rows[0].issues, 'Awaiting approval');
});

test('userRows: a rejected account is flagged rejected (re-approvable)', () => {
  const rows = userRows([{ userId: 'r1', email: 'rej@x.com', role: 'member', status: 'rejected', deviceCount: 0, openAlerts: 0, issues: ['Rejected'] }], 'UTC');
  assert.equal(rows[0].rejected, true);
  assert.equal(rows[0].pendingApproval, false);
});

test('userRows: entitlementExpired appends " (expired)" to the formatted expiry timestamp', () => {
  const users = [{
    userId: 'u2', email: 'b@x.com', role: 'member', status: 'active',
    importEnabled: false, exportEnabled: false, monitoringEnabled: true,
    entitlementExpiresAt: '2026-07-16T14:05:33.000Z', entitlementExpired: true,
    deviceCount: 0, openAlerts: 0, issues: ['Access expired'],
  }];
  const rows = userRows(users, 'UTC');
  assert.equal(rows[0].expires, '2026-07-16 14:05:33 (expired)');
  assert.equal(rows[0].issues, 'Access expired');
  assert.equal(rows[0].hasIssues, true);
});

test('userRows: a non-expired entitlement with an expiry timestamp renders without the "(expired)" suffix', () => {
  const users = [{
    userId: 'u2b', email: 'b2@x.com', role: 'member', status: 'active',
    entitlementExpiresAt: '2026-07-16T14:05:33.000Z', entitlementExpired: false,
    deviceCount: 0, openAlerts: 0, issues: [],
  }];
  const rows = userRows(users, 'UTC');
  assert.equal(rows[0].expires, '2026-07-16 14:05:33');
});

test('userRows: multiple issues are joined with "; "', () => {
  const users = [{
    userId: 'u3', email: 'c@x.com', role: 'member', status: 'suspended',
    deviceCount: 0, openAlerts: 0, issues: ['Suspended', 'Notice not accepted'],
  }];
  const rows = userRows(users, 'UTC');
  assert.equal(rows[0].issues, 'Suspended; Notice not accepted');
  assert.equal(rows[0].hasIssues, true);
});

test('userRows: importEnabled/exportEnabled map to Yes/No, monitoringEnabled maps to On/Paused', () => {
  const users = [{
    userId: 'u4', email: 'd@x.com', role: 'member', status: 'active',
    importEnabled: true, exportEnabled: true, monitoringEnabled: false,
    deviceCount: 0, openAlerts: 0, issues: [],
  }];
  const rows = userRows(users, 'UTC');
  assert.equal(rows[0].importEnabled, 'Yes');
  assert.equal(rows[0].exportEnabled, 'Yes');
  assert.equal(rows[0].monitoring, 'Paused');
});

test('userRows: a null email (decrypt failure) and null role/status degrade to an em dash', () => {
  const users = [{
    userId: 'u5', email: null, role: null, status: null,
    deviceCount: 0, openAlerts: 0, issues: [],
  }];
  const rows = userRows(users, 'UTC');
  assert.equal(rows[0].email, '—');
  assert.equal(rows[0].role, '—');
  assert.equal(rows[0].status, '—');
});

test('userRows: a hostile email/issues payload renders inert', () => {
  const users = [{
    userId: 'u6', email: '<script>e</script>', role: 'member', status: 'active',
    deviceCount: 0, openAlerts: 0, issues: ['<script>alert(1)</script>', 'Suspended'],
  }];
  const rows = userRows(users, 'UTC');
  assert.ok(!rows[0].email.includes('<script>'));
  assert.ok(!rows[0].issues.includes('<script>'));
  assert.equal(rows[0].email, '&lt;script&gt;e&lt;/script&gt;');
  assert.equal(rows[0].issues, '&lt;script&gt;alert(1)&lt;/script&gt;; Suspended');
});

test('userRows: empty array yields empty array', () => {
  assert.deepEqual(userRows([], 'UTC'), []);
  assert.deepEqual(userRows(undefined, 'UTC'), []);
});

// F3: createdByEmail ("Added by") + awaitingFirstSignIn (onboarding).
test('userRows: createdByEmail is escaped/null-safe; awaitingFirstSignIn is true only for an active user with zero devices', () => {
  const users = [
    { userId: 'u7', email: 'e7@x.com', role: 'member', status: 'active', createdByEmail: 'boss@x.com', deviceCount: 0, openAlerts: 0, issues: [] },
    { userId: 'u8', email: 'e8@x.com', role: 'member', status: 'active', createdByEmail: null, deviceCount: 3, openAlerts: 0, issues: [] },
    { userId: 'u9', email: 'e9@x.com', role: 'member', status: 'suspended', createdByEmail: null, deviceCount: 0, openAlerts: 0, issues: ['Suspended'] },
  ];
  const rows = userRows(users, 'UTC');
  assert.equal(rows[0].createdByEmail, 'boss@x.com');
  assert.equal(rows[0].awaitingFirstSignIn, true, 'active + zero devices = awaiting first sign-in');
  assert.equal(rows[1].createdByEmail, '—');
  assert.equal(rows[1].awaitingFirstSignIn, false, 'has devices already');
  assert.equal(rows[2].awaitingFirstSignIn, false, 'not active (suspended), even with zero devices');
});

test('userRows: a hostile createdByEmail renders inert', () => {
  const users = [{ userId: 'u10', email: 'e10@x.com', role: 'member', status: 'active', createdByEmail: '<script>b</script>', deviceCount: 0, openAlerts: 0, issues: [] }];
  const rows = userRows(users, 'UTC');
  assert.ok(!rows[0].createdByEmail.includes('<script>'));
  assert.equal(rows[0].createdByEmail, '&lt;script&gt;b&lt;/script&gt;');
});

// F2: statusAction/statusActionLabel — the inline Suspend/Reactivate toggle.
test('userRows: statusAction is "suspend" for an active user, "reactivate" for a suspended one, null otherwise', () => {
  const users = [
    { userId: 'a', email: 'a@x.com', status: 'active', deviceCount: 0, openAlerts: 0, issues: [] },
    { userId: 'b', email: 'b@x.com', status: 'suspended', deviceCount: 0, openAlerts: 0, issues: ['Suspended'] },
    { userId: 'c', email: 'c@x.com', status: 'pending', deviceCount: 0, openAlerts: 0, issues: [] },
    { userId: 'd', email: 'd@x.com', status: 'deprovisioned', deviceCount: 0, openAlerts: 0, issues: ['Deprovisioned'] },
  ];
  const rows = userRows(users, 'UTC');
  assert.equal(rows[0].statusAction, 'suspend');
  assert.equal(rows[0].statusActionLabel, 'Suspend');
  assert.equal(rows[1].statusAction, 'reactivate');
  assert.equal(rows[1].statusActionLabel, 'Reactivate');
  assert.equal(rows[2].statusAction, null);
  assert.equal(rows[2].statusActionLabel, null);
  assert.equal(rows[3].statusAction, null);
  assert.equal(rows[3].statusActionLabel, null);
});

// ===========================================================================
// userDeviceRows(devices, userId, tz) — F3: per-user device expand panel,
// reusing the SAME GET /admin/reports/devices feed (client-side filter, no
// new endpoint). Mirrors deviceRows' field mapping/escaping exactly.
// ===========================================================================

test('userDeviceRows: returns only the matching user\'s devices, mapped through deviceRows', () => {
  const devices = [
    { deviceId: 'd1', userId: 'u1', status: 'active', firstSeen: '2026-07-01T00:00:00.000Z', lastSeen: '2026-07-16T14:05:33.000Z', appVersion: '1.0', os: 'windows', lastIp: '1.2.3.4', geo: null, ipv4: '1.2.3.4', geo4: null, ipv6: null, geo6: null },
    { deviceId: 'd2', userId: 'u2', status: 'active', firstSeen: null, lastSeen: null, appVersion: null, os: null, lastIp: null, geo: null, ipv4: null, geo4: null, ipv6: null, geo6: null },
  ];
  const model = userDeviceRows(devices, 'u1', 'UTC');
  assert.equal(model.empty, false);
  assert.equal(model.rows.length, 1);
  assert.equal(model.rows[0].deviceId, 'd1');
  assert.equal(model.rows[0].userId, 'u1');
});

test('userDeviceRows: a user with no devices returns the onboarding sentinel {empty:true, rows:[]}', () => {
  const devices = [{ deviceId: 'd1', userId: 'someone-else', status: 'active' }];
  const model = userDeviceRows(devices, 'u-nobody', 'UTC');
  assert.deepEqual(model, { empty: true, rows: [] });
});

test('userDeviceRows: an empty/undefined device list also yields the onboarding sentinel', () => {
  assert.deepEqual(userDeviceRows([], 'u1', 'UTC'), { empty: true, rows: [] });
  assert.deepEqual(userDeviceRows(undefined, 'u1', 'UTC'), { empty: true, rows: [] });
});

test('userDeviceRows: hostile fields in a matched device still render inert (delegates to deviceRows escaping)', () => {
  const devices = [{ deviceId: '<script>d</script>', userId: 'u1', status: 'active', os: '<img src=x onerror=alert(1)>' }];
  const model = userDeviceRows(devices, 'u1', 'UTC');
  assert.equal(model.empty, false);
  assert.ok(!model.rows[0].deviceId.includes('<script>'));
  assert.ok(!model.rows[0].os.includes('<img'));
});

// ===========================================================================
// usageOverviewRows(rows, tz) — GET /admin/reports/usage .rows (spec
// f1a-usage-backend). Shared byte-identically with the desktop admin UI
// (parity-tested there); pre-escaped cells only, no DOM/fetch.
// ===========================================================================

test('usageOverviewRows: maps every documented field for a normal row', () => {
  const rows = [{
    userId: 'u1', email: 'a@x.com', accountLabel: 'work@example.com',
    accountUuid: 'acct-1', organizationUuid: 'org-1',
    fiveHour: 40, sevenDay: 65.5,
    fiveHourResetsAt: '2026-07-17T15:00:00.000Z', sevenDayResetsAt: '2026-07-19T13:30:00.000Z',
    capturedAt: '2026-07-17T10:00:00.000Z',
    updatedAt: '2026-07-17T14:05:33.000Z',
  }];
  const out = usageOverviewRows(rows, 'UTC');
  assert.deepEqual(out[0], {
    userId: 'u1', email: 'a@x.com', accountLabel: 'work@example.com',
    accountUuid: 'acct-1', organizationUuid: 'org-1',
    fiveHour: '40%', sevenDay: '65.5%',
    fiveHourReset: '2026-07-17 15:00:00', sevenDayReset: '2026-07-19 13:30:00',
    updated: '2026-07-17 14:05:33',
  });
});

test('usageOverviewRows: a missing reset timestamp degrades to an em dash', () => {
  const rows = [{
    userId: 'u9', email: 'z@x.com', accountLabel: 'lbl',
    accountUuid: 'a9', organizationUuid: 'o9',
    fiveHour: 12, sevenDay: 34,
    fiveHourResetsAt: null, sevenDayResetsAt: null,
    updatedAt: '2026-07-17T00:00:00.000Z',
  }];
  const out = usageOverviewRows(rows, 'UTC');
  assert.equal(out[0].fiveHourReset, '—');
  assert.equal(out[0].sevenDayReset, '—');
});

test('usageOverviewRows: null fiveHour/sevenDay degrade to an em dash, not "null%"', () => {
  const rows = [{
    userId: 'u2', email: 'b@x.com', accountLabel: 'lbl',
    accountUuid: 'a2', organizationUuid: 'o2',
    fiveHour: null, sevenDay: null, updatedAt: null,
  }];
  const out = usageOverviewRows(rows, 'UTC');
  assert.equal(out[0].fiveHour, '—');
  assert.equal(out[0].sevenDay, '—');
  assert.equal(out[0].updated, '—');
});

test('usageOverviewRows: a null email/accountLabel (decrypt failure) degrades to an em dash', () => {
  const rows = [{
    userId: 'u3', email: null, accountLabel: null,
    accountUuid: 'a3', organizationUuid: 'o3',
    fiveHour: 10, sevenDay: 10, updatedAt: '2026-07-17T00:00:00.000Z',
  }];
  const out = usageOverviewRows(rows, 'UTC');
  assert.equal(out[0].email, '—');
  assert.equal(out[0].accountLabel, '—');
});

test('usageOverviewRows: a hostile email/accountLabel payload renders inert', () => {
  const rows = [{
    userId: 'u4', email: '<script>e</script>', accountLabel: '<img src=x onerror=alert(1)>',
    accountUuid: 'a4', organizationUuid: 'o4',
    fiveHour: 5, sevenDay: 5, updatedAt: '2026-07-17T00:00:00.000Z',
  }];
  const out = usageOverviewRows(rows, 'UTC');
  assert.ok(!out[0].email.includes('<script>'));
  assert.ok(!out[0].accountLabel.includes('<img'));
  assert.equal(out[0].email, '&lt;script&gt;e&lt;/script&gt;');
});

test('usageOverviewRows: empty array yields empty array', () => {
  assert.deepEqual(usageOverviewRows([], 'UTC'), []);
  assert.deepEqual(usageOverviewRows(undefined, 'UTC'), []);
});

// ===========================================================================
// toCsv(rows, columns) / csvColumns(key) — client-side CSV export of a
// report's already-fetched RAW rows (full population). Pure, no DOM/fetch.
// ===========================================================================

test('toCsv: header row from column headers, then one line per row (CRLF)', () => {
  const cols = [{ key: 'a', header: 'A' }, { key: 'b', header: 'B' }];
  const out = toCsv([{ a: '1', b: '2' }, { a: '3', b: '4' }], cols);
  assert.equal(out, 'A,B\r\n1,2\r\n3,4');
});

test('toCsv: empty/absent rows yields just the header line', () => {
  const cols = [{ key: 'a', header: 'A' }];
  assert.equal(toCsv([], cols), 'A');
  assert.equal(toCsv(undefined, cols), 'A');
});

test('toCsv: falls back to the key when a column has no header', () => {
  assert.equal(toCsv([{ x: '1' }], [{ key: 'x' }]), 'x\r\n1');
});

test('toCsv: quotes cells containing comma, quote, or newline (doubling quotes)', () => {
  const cols = [{ key: 'v', header: 'V' }];
  assert.equal(toCsv([{ v: 'a,b' }], cols), 'V\r\n"a,b"');
  assert.equal(toCsv([{ v: 'a"b' }], cols), 'V\r\n"a""b"');
  assert.equal(toCsv([{ v: 'a\nb' }], cols), 'V\r\n"a\nb"');
});

test('toCsv: neutralizes spreadsheet formula injection with a leading quote', () => {
  const cols = [{ key: 'v', header: 'V' }];
  assert.equal(toCsv([{ v: '=SUM(A1:A2)' }], cols), "V\r\n'=SUM(A1:A2)");
  assert.equal(toCsv([{ v: '+1' }], cols), "V\r\n'+1");
  assert.equal(toCsv([{ v: '-1' }], cols), "V\r\n'-1");
  assert.equal(toCsv([{ v: '@x' }], cols), "V\r\n'@x");
});

test('toCsv: arrays render as "a; b", null/undefined/objects as empty', () => {
  const cols = [{ key: 'v', header: 'V' }];
  assert.equal(toCsv([{ v: ['us', 'in'] }], cols), 'V\r\nus; in');
  assert.equal(toCsv([{ v: null }], cols), 'V\r\n');
  assert.equal(toCsv([{ v: { a: 1 } }], cols), 'V\r\n');
});

test('toCsv: booleans and numbers stringify (0 and false are not dropped)', () => {
  const cols = [{ key: 'n', header: 'N' }, { key: 'b', header: 'B' }];
  assert.equal(toCsv([{ n: 0, b: false }], cols), 'N,B\r\n0,false');
});

test('csvColumns: usage and users return non-empty specs; unknown returns []', () => {
  assert.ok(csvColumns('usage').length > 0);
  assert.ok(csvColumns('users').length > 0);
  assert.ok(csvColumns('usage').every((c) => typeof c.key === 'string' && typeof c.header === 'string'));
  assert.deepEqual(csvColumns('nope'), []);
});

// ===========================================================================
// effectivePolicyModel(u, tz) — net per-capability policy for one user row
// ===========================================================================

test('effectivePolicyModel: an active user with import on / export off reads correctly', () => {
  const m = effectivePolicyModel({
    status: 'active', importEnabled: true, exportEnabled: false, monitoringEnabled: true,
    geoFenceCountries: [], blockedCountries: [],
  }, 'UTC');
  assert.equal(m.access.tone, 'ok');
  const byName = Object.fromEntries(m.rows.map((r) => [r.name, r]));
  assert.equal(byName['Sign-in access'].value, 'Allowed');
  assert.equal(byName['Import accounts'].value, 'Allowed');
  assert.equal(byName['Export accounts'].value, 'Blocked');
  assert.equal(byName['Sign-in location'].value, 'Anywhere');
});

test('effectivePolicyModel: suspended / expired access blocks sign-in (danger)', () => {
  const susp = effectivePolicyModel({ status: 'suspended' }, 'UTC');
  assert.equal(susp.access.tone, 'danger');
  assert.equal(susp.rows.find((r) => r.name === 'Sign-in access').value, 'Blocked');

  const exp = effectivePolicyModel({ status: 'active', entitlementExpired: true, entitlementExpiresAt: '2020-01-01T00:00:00.000Z' }, 'UTC');
  assert.equal(exp.access.tone, 'danger');
  assert.match(exp.rows.find((r) => r.name === 'Sign-in access').detail, /expired/i);
});

test('effectivePolicyModel: a blocked-country deny-list surfaces on the location row', () => {
  const m = effectivePolicyModel({ status: 'active', blockedCountries: ['RU', 'KP'], geoFenceCountries: ['IN'] }, 'UTC');
  const loc = m.rows.find((r) => r.name === 'Sign-in location');
  assert.equal(loc.value, 'Restricted');
  assert.match(loc.detail, /Blocked from: RU, KP/);
});

test('effectivePolicyModel: a hostile country payload is escaped in the detail', () => {
  const m = effectivePolicyModel({ status: 'active', blockedCountries: ['<img src=x>'] }, 'UTC');
  const loc = m.rows.find((r) => r.name === 'Sign-in location');
  assert.ok(!loc.detail.includes('<img'), loc.detail);
});

// ===========================================================================
// verifyModel(auditVerify, permVerify)
// ===========================================================================

test('verifyModel: ok:true shapes carry count/headSeq/headHash through', () => {
  const audit = { ok: true, count: 42, headSeq: 42, headHash: 'abcdef123' };
  const perms = { ok: true, count: 5, headSeq: 5, headHash: '9998887' };
  const model = verifyModel(audit, perms);
  assert.equal(model.audit.ok, true);
  assert.equal(model.audit.count, 42);
  assert.equal(model.audit.headSeq, 42);
  assert.equal(model.audit.headHash, 'abcdef123');
  assert.equal(model.permissions.ok, true);
  assert.equal(model.permissions.count, 5);
});

test('verifyModel: ok:false shapes carry the failure reason and never crash on extra context fields', () => {
  const audit = { ok: false, reason: 'anchor_signature_invalid', seqHigh: 10 };
  const perms = { ok: false, reason: 'no_anchor_for_start' };
  const model = verifyModel(audit, perms);
  assert.equal(model.audit.ok, false);
  assert.equal(model.audit.reason, 'anchor_signature_invalid');
  assert.equal(model.permissions.ok, false);
  assert.equal(model.permissions.reason, 'no_anchor_for_start');
});

test('verifyModel: a hostile reason string renders inert', () => {
  const model = verifyModel({ ok: false, reason: '<script>bad()</script>' }, { ok: true, count: 0, headSeq: 0 });
  assert.ok(!model.audit.reason.includes('<script>'));
});

// ===========================================================================
// UMD shape
// ===========================================================================

test('UMD: module.exports carries the full documented API surface', () => {
  for (const name of ['esc', 'escAttr', 'formatTs', 'formatRelative', 'overviewModel', 'timelineRows', 'deviceRows', 'userDeviceRows', 'ipGeoRows', 'alertRows', 'traceModel', 'transferRows', 'userRows', 'usageOverviewRows', 'verifyModel', 'toCsv', 'csvColumns', 'effectivePolicyModel']) {
    assert.equal(typeof AdminViews[name], 'function', `AdminViews.${name} must be a function`);
  }
});
