// Shared admin view-model module (Phase 5, Task 6). Pure data -> view-model
// functions used byte-identically by BOTH admin UIs: the web console
// (backend/public/admin.js, Task 7) and the desktop in-app admin section
// (desktop/src/renderer/adminviews.js, Task 9 — parity-tested exact copy).
//
// Hard rule: NO DOM access, NO fetch, NO window/global state in here. Every
// function is a pure (data, ...) -> value transform so it can run identically
// under a browser <script> tag, the Electron renderer, and plain `node --test`
// (see backend/adminviews.test.js). Every data-derived string that ends up in
// a returned "cell" is passed through esc() so callers can drop the result
// straight into innerHTML without re-escaping (and without ever forgetting to).
//
// Classic-script-compatible UMD wrapper: exposes global.AdminViews for a
// plain <script> load, and module.exports for require()/node --test.
(function (global) {
  'use strict';

  // ---------------------------------------------------------------------
  // esc / escAttr — string-based HTML escaping (no DOM textContent trick;
  // this module cannot assume a document exists).
  // ---------------------------------------------------------------------

  function esc(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // esc() already neutralizes quotes, so it is already attribute-safe; kept
  // as a distinct named function (matching the public/app.js convention) so
  // call sites document their intent and the two can diverge later if a
  // context ever needs it.
  function escAttr(s) {
    return esc(s);
  }

  // ---------------------------------------------------------------------
  // formatTs / formatRelative — timestamps rendered in an explicit IANA zone
  // (spec §6.9: stored/transported as UTC, rendered in the viewer's local
  // zone by the client). No timeZone argument = the viewer's own zone
  // (Intl's default when timeZone is omitted from the options).
  // ---------------------------------------------------------------------

  function pad2(n) {
    return n < 10 ? '0' + n : String(n);
  }

  // 'YYYY-MM-DD HH:mm:ss', 24h, in the given IANA zone. Uses
  // Intl.DateTimeFormat#formatToParts (not a locale-formatted string) so the
  // output shape never depends on locale punctuation conventions (some ICU
  // locales/versions separate date and time with a comma). hourCycle:'h23'
  // forces true 00-23 hours (hour12:false alone is not sufficient in every
  // locale/ICU version).
  function formatTs(iso, timeZone) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    var opts = {
      hourCycle: 'h23',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    };
    if (timeZone) opts.timeZone = timeZone;
    var parts = new Intl.DateTimeFormat('en-US', opts).formatToParts(d);
    var map = {};
    for (var i = 0; i < parts.length; i++) map[parts[i].type] = parts[i].value;
    return map.year + '-' + map.month + '-' + map.day + ' ' + map.hour + ':' + map.minute + ':' + map.second;
  }

  // Coarse "how long ago" bucketing: 'just now' (<1m), 'Xm ago' (<1h),
  // 'Xh ago' (<1d), 'Xd ago' beyond. A future timestamp (clock skew) clamps
  // to 'just now' rather than going negative.
  function formatRelative(iso, nowMs) {
    if (!iso) return '—';
    var t = Date.parse(iso);
    if (isNaN(t)) return '—';
    var now = nowMs == null ? Date.now() : nowMs;
    var diff = now - t;
    if (diff < 0) diff = 0;
    if (diff < 60000) return 'just now';
    if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
    if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
    return Math.floor(diff / 86400000) + 'd ago';
  }

  // ---------------------------------------------------------------------
  // formatGeo — coarse geo (spec §6.5: country/region/city/ASN only) as
  // "City, Region, CC"; missing pieces are simply omitted, '—' when empty.
  // ---------------------------------------------------------------------

  function formatGeo(geo) {
    if (!geo) return '—';
    var parts = [];
    if (geo.city) parts.push(String(geo.city));
    if (geo.region) parts.push(String(geo.region));
    if (geo.country) parts.push(String(geo.country));
    if (!parts.length) return '—';
    return esc(parts.join(', '));
  }

  function escOr(v) {
    return v == null || v === '' ? '—' : esc(v);
  }

  // ---------------------------------------------------------------------
  // overviewModel({devices, storage, timeline, nowMs})
  // KPI summary for the Overview page: active users/devices + storage
  // passthrough. Not a row builder — a small numeric model.
  // Returns: {activeUsers, activeDevices, totalDevices, windowDays, storagePercent, storageEstimatedBytes, storageCapacityBytes}
  // ---------------------------------------------------------------------

  function overviewModel(input) {
    input = input || {};
    var devices = input.devices || [];
    var storage = input.storage || {};
    var timeline = input.timeline || {};
    var nowMs = input.nowMs == null ? Date.now() : input.nowMs;
    var events = timeline.events || [];

    // Set, not a plain object keyed by userId — a userId of "__proto__" (or
    // "toString"/"constructor"/etc.) would otherwise collide with inherited
    // Object.prototype properties and be silently undercounted.
    var userIds = new Set();
    for (var i = 0; i < events.length; i++) {
      var uid = events[i] && events[i].userId;
      if (uid != null) userIds.add(uid);
    }
    var activeUsers = userIds.size;

    var activeDevices = 0;
    for (var j = 0; j < devices.length; j++) {
      var dev = devices[j];
      if (!dev || !dev.lastSeen) continue;
      var t = Date.parse(dev.lastSeen);
      if (isNaN(t)) continue;
      if (Math.abs(nowMs - t) <= 86400000) activeDevices++;
    }

    return {
      activeUsers: activeUsers,
      activeDevices: activeDevices,
      totalDevices: devices.length,
      windowDays: timeline.windowDays == null ? null : timeline.windowDays,
      storagePercent: storage.percent == null ? null : storage.percent,
      storageEstimatedBytes: storage.estimatedBytes == null ? null : storage.estimatedBytes,
      storageCapacityBytes: storage.capacityBytes == null ? null : storage.capacityBytes,
    };
  }

  // ---------------------------------------------------------------------
  // timelineRows(events, tz) — GET /admin/reports/timeline .events
  // Returns: {seq, time, eventType, severity, userId, deviceId, result, reason, geo, ip}
  // ---------------------------------------------------------------------

  function timelineRows(events, tz) {
    return (events || []).map(function (e) {
      e = e || {};
      return {
        seq: e.seq == null ? null : e.seq,
        time: esc(formatTs(e.serverTs, tz)),
        eventType: escOr(e.eventType),
        severity: escOr(e.severity),
        userId: escOr(e.userId),
        email: escOr(e.email),
        deviceId: escOr(e.deviceId),
        result: escOr(e.result),
        reason: escOr(e.reason),
        geo: formatGeo(e.geo),
        ip: escOr(e.ip),
      };
    });
  }

  // ---------------------------------------------------------------------
  // deviceRows(devices, tz) — GET /admin/reports/devices .devices, full set
  // of columns including both IP families + their geo.
  // Returns: {deviceId, userId, status, firstSeen, lastSeen, appVersion, os, ipv4, geo4, ipv6, geo6, lastIp, geo}
  // ---------------------------------------------------------------------

  function deviceRows(devices, tz) {
    return (devices || []).map(function (d) {
      d = d || {};
      return {
        deviceId: escOr(d.deviceId),
        userId: escOr(d.userId),
        email: escOr(d.email),
        status: escOr(d.status),
        firstSeen: esc(formatTs(d.firstSeen, tz)),
        lastSeen: esc(formatTs(d.lastSeen, tz)),
        appVersion: escOr(d.appVersion),
        os: escOr(d.os),
        ipv4: escOr(d.ipv4),
        geo4: formatGeo(d.geo4),
        ipv6: escOr(d.ipv6),
        geo6: formatGeo(d.geo6),
        lastIp: escOr(d.lastIp),
        geo: formatGeo(d.geo),
      };
    });
  }

  // ---------------------------------------------------------------------
  // userDeviceRows(devices, userId, tz) — F3: client-side filter of the SAME
  // GET /admin/reports/devices feed the Devices tab uses (deviceRows above),
  // scoped to one user for the Users-tab per-user device expand panel. No
  // new endpoint/route: reuses deviceRows' exact field mapping/escaping.
  // A user with no devices yet (onboarding — created but never signed in)
  // returns {empty:true, rows:[]} so the caller can render the "No device
  // yet — waiting for first sign-in." sentinel.
  // Returns: {empty, rows:[{deviceId,userId,status,firstSeen,lastSeen,appVersion,os,ipv4,geo4,ipv6,geo6,lastIp,geo}]}
  // ---------------------------------------------------------------------

  function userDeviceRows(devices, userId, tz) {
    var filtered = (devices || []).filter(function (d) { return d && d.userId === userId; });
    return { empty: filtered.length === 0, rows: deviceRows(filtered, tz) };
  }

  // ---------------------------------------------------------------------
  // ipGeoRows(devices, tz) — the IP & Geo view: narrower, per-device slice
  // of deviceRows focused on where each device connects from.
  // Returns: {deviceId, userId, lastSeen, ipv4, geo4, ipv6, geo6}
  // ---------------------------------------------------------------------

  function ipGeoRows(devices, tz) {
    return (devices || []).map(function (d) {
      d = d || {};
      return {
        deviceId: escOr(d.deviceId),
        userId: escOr(d.userId),
        email: escOr(d.email),
        lastSeen: esc(formatTs(d.lastSeen, tz)),
        ipv4: escOr(d.ipv4),
        geo4: formatGeo(d.geo4),
        ipv6: escOr(d.ipv6),
        geo6: formatGeo(d.geo6),
      };
    });
  }

  // ---------------------------------------------------------------------
  // alertRows(alerts, tz) — GET /admin/reports/alerts .alerts
  // Returns: {seq, time, severity, eventType, reason, userId, deviceId, email, reasonLabel, alertsMuted}
  // email/reasonLabel/alertsMuted (E3) are pre-joined/pre-escaped server-side
  // view-model additions (reporting.alertsFeed) — additive only, so an admin
  // sees "whose alert, what happened" without a second lookup.
  // ---------------------------------------------------------------------

  function alertRows(alerts, tz) {
    return (alerts || []).map(function (a) {
      a = a || {};
      return {
        seq: a.seq == null ? null : a.seq,
        time: esc(formatTs(a.serverTs, tz)),
        severity: escOr(a.severity),
        eventType: escOr(a.eventType),
        reason: escOr(a.reason),
        userId: escOr(a.userId),
        deviceId: escOr(a.deviceId),
        email: escOr(a.email),
        reasonLabel: escOr(a.reasonLabel),
        alertsMuted: !!a.alertsMuted,
      };
    });
  }

  // ---------------------------------------------------------------------
  // traceModel(trace, tz) — GET /watermarks/trace: one export + its imports.
  // Flags any import whose userId differs from the exporter (mirrors the
  // Task 5 server-side cross_user_import anomaly) both per-row and overall.
  // Returns: {watermarkId, export:{userId,deviceId,exportedAt,fileSha256}, imports:[{userId,deviceId,at,ip,crossUser}], importCount, crossUser}
  // ---------------------------------------------------------------------

  function traceModel(trace, tz) {
    trace = trace || {};
    var exp = trace.export || {};
    var imports = (trace.imports || []).map(function (imp) {
      imp = imp || {};
      var crossUser = exp.userId != null && imp.userId != null && imp.userId !== exp.userId;
      return {
        userId: escOr(imp.userId),
        deviceId: escOr(imp.deviceId),
        at: esc(formatTs(imp.at, tz)),
        ip: escOr(imp.ip),
        crossUser: crossUser,
      };
    });
    var anyCrossUser = imports.some(function (i) { return i.crossUser; });
    return {
      watermarkId: escOr(trace.watermarkId),
      export: {
        userId: escOr(exp.userId),
        deviceId: escOr(exp.deviceId),
        exportedAt: esc(formatTs(exp.exportedAt, tz)),
        fileSha256: escOr(exp.fileSha256),
      },
      imports: imports,
      importCount: imports.length,
      crossUser: anyCrossUser,
    };
  }

  // ---------------------------------------------------------------------
  // transferRows(transfers, tz) — GET /admin/reports/transfers .transfers.
  // Same cross-user detection as traceModel, exposed as a flag + a ready-
  // to-render badge cell (empty string when not cross-user).
  // Returns: {watermarkId, exportUserId, exportDeviceId, exportedAt, fileSha256, importCount, crossUser, badge}
  // ---------------------------------------------------------------------

  function transferRows(transfers, tz) {
    return (transfers || []).map(function (t) {
      t = t || {};
      var exp = t.export || {};
      var imports = (t.imports || []).map(function (imp) {
        imp = imp || {};
        var crossUserImp = exp.userId != null && imp.userId != null && imp.userId !== exp.userId;
        return {
          email: escOr(imp.email),
          userId: escOr(imp.userId),
          deviceId: escOr(imp.deviceId),
          at: esc(formatTs(imp.at, tz)),
          ip: escOr(imp.ip),
          crossUser: crossUserImp,
        };
      });
      var crossUser = imports.some(function (i) { return i.crossUser; });
      return {
        watermarkId: escOr(t.watermarkId),
        exportEmail: escOr(exp.email),
        exportUserId: escOr(exp.userId),
        exportDeviceId: escOr(exp.deviceId),
        exportedAt: esc(formatTs(exp.exportedAt, tz)),
        fileSha256: escOr(exp.fileSha256),
        imports: imports,
        importCount: t.importCount == null ? imports.length : t.importCount,
        crossUser: crossUser,
        badge: crossUser ? 'cross-user' : '',
      };
    });
  }

  // ---------------------------------------------------------------------
  // userRows(users, tz) — GET /admin/reports/users .users (users with issues
  // sorted first by the server). hasIssues drives the caller's row-alert
  // highlight so an admin can spot "which user has which problem" at a
  // glance; issues is the pre-joined, pre-escaped human-readable list.
  //
  // F3 additive fields: createdByEmail ("Added by", escaped/null-safe) and
  // awaitingFirstSignIn (true when a just-created active user has no device
  // yet — deliberately NOT folded into issues[], see reporting.js/F3 design
  // notes, so the existing deterministic sort + deepEqual(issues) tests are
  // unaffected).
  // F2 additive fields: statusAction ('suspend' when active, 'reactivate'
  // when suspended, else null) + statusActionLabel, so the Users-tab row can
  // render a single inline Suspend/Reactivate toggle without recomputing the
  // status machine client-side.
  // Returns: {userId, email, role, status, importEnabled, exportEnabled, monitoring, expires, devices, alerts, issues, hasIssues, createdByEmail, awaitingFirstSignIn, statusAction, statusActionLabel}
  // ---------------------------------------------------------------------

  function userRows(users, tz) {
    return (users || []).map(function (u) {
      u = u || {};
      var issues = u.issues || [];
      var expires = formatTs(u.entitlementExpiresAt, tz);
      if (u.entitlementExpired && expires !== '—') expires += ' (expired)';
      var deviceCount = u.deviceCount == null ? 0 : u.deviceCount;
      var statusAction = u.status === 'active' ? 'suspend' : (u.status === 'suspended' ? 'reactivate' : null);
      var statusActionLabel = statusAction === 'suspend' ? 'Suspend' : (statusAction === 'reactivate' ? 'Reactivate' : null);
      return {
        userId: escOr(u.userId),
        email: escOr(u.email),
        role: escOr(u.role),
        status: escOr(u.status),
        importEnabled: u.importEnabled ? 'Yes' : 'No',
        exportEnabled: u.exportEnabled ? 'Yes' : 'No',
        monitoring: u.monitoringEnabled ? 'On' : 'Paused',
        expires: esc(expires),
        devices: String(deviceCount),
        alerts: String(u.openAlerts == null ? 0 : u.openAlerts),
        issues: issues.length ? esc(issues.join('; ')) : '—',
        hasIssues: issues.length > 0,
        createdByEmail: escOr(u.createdByEmail),
        awaitingFirstSignIn: deviceCount === 0 && u.status === 'active',
        statusAction: statusAction,
        statusActionLabel: statusActionLabel,
        // OTP-free signup: a pending self-signup awaits admin approval; the
        // Users row shows Approve + Reject. A rejected account can be re-approved.
        pendingApproval: u.status === 'pending',
        rejected: u.status === 'rejected',
      };
    });
  }

  // ---------------------------------------------------------------------
  // usageOverviewRows(rows, tz) — GET /admin/reports/usage .rows (spec
  // f1a-usage-backend: "who used how much of each Claude account's limits
  // and when"). Byte-identical shared with the desktop admin UI (parity-
  // tested there). Percent cells render as "N%" or an em dash when the
  // account never reported a value; email/accountLabel are decrypted,
  // admin-only PII from the server and are escaped here like every other
  // row builder in this module.
  // Returns: {userId, email, accountLabel, accountUuid, organizationUuid, fiveHour, sevenDay, updated}
  // ---------------------------------------------------------------------

  function pctOrDash(v) {
    return v == null ? '—' : String(v) + '%';
  }

  // ---------------------------------------------------------------------
  // CSV export (client-side, FULL population). toCsv(rows, columns) is a pure
  // RFC-4180-ish serializer; `columns` is [{key, header}]. Cells are made safe
  // against spreadsheet formula injection (a leading =,+,-,@,tab,CR gets a
  // leading single quote) and quoted when they contain a comma/quote/newline.
  // Arrays render "a; b"; null/undefined/objects render "". Both admin UIs feed
  // it a report's ALREADY-FETCHED raw rows — no server round-trip, no top-N
  // truncation. csvColumns(key) returns the shared per-report column spec.
  // Byte-identical across both adminviews.js copies (parity-tested).
  // ---------------------------------------------------------------------

  function csvCell(v) {
    var s;
    if (v == null) s = '';
    else if (Array.isArray(v)) s = v.join('; ');
    else if (typeof v === 'object') s = '';
    else s = String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // neutralize spreadsheet formula injection
    if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"'; // RFC-4180 quoting
    return s;
  }

  function toCsv(rows, columns) {
    var cols = columns || [];
    var list = rows || [];
    var head = cols.map(function (c) { return csvCell(c.header != null ? c.header : c.key); }).join(',');
    if (!list.length) return head; // header-only when there are no rows (NOT when a row is all-empty)
    var body = list.map(function (r) {
      r = r || {};
      return cols.map(function (c) { return csvCell(r[c.key]); }).join(',');
    }).join('\r\n');
    return head + '\r\n' + body;
  }

  var CSV_COLUMNS = {
    usage: [
      { key: 'email', header: 'Email' },
      { key: 'accountLabel', header: 'Account' },
      { key: 'accountUuid', header: 'Account UUID' },
      { key: 'organizationUuid', header: 'Organization UUID' },
      { key: 'fiveHour', header: '5-hour %' },
      { key: 'sevenDay', header: 'Weekly %' },
      { key: 'fiveHourResetsAt', header: '5-hour resets at' },
      { key: 'sevenDayResetsAt', header: 'Weekly resets at' },
      { key: 'capturedAt', header: 'Captured at' },
      { key: 'updatedAt', header: 'Updated at' },
      { key: 'userId', header: 'User ID' },
    ],
    users: [
      { key: 'email', header: 'Email' },
      { key: 'role', header: 'Role' },
      { key: 'status', header: 'Status' },
      { key: 'emailVerified', header: 'Verified' },
      { key: 'importEnabled', header: 'Import allowed' },
      { key: 'exportEnabled', header: 'Export allowed' },
      { key: 'monitoringEnabled', header: 'Monitoring on' },
      { key: 'entitlementExpiresAt', header: 'Access expires' },
      { key: 'entitlementExpired', header: 'Access expired' },
      { key: 'geoFenceCountries', header: 'Geo-fence (allow)' },
      { key: 'blockedCountries', header: 'Blocked countries' },
      { key: 'openAlerts', header: 'Open alerts' },
      { key: 'deviceCount', header: 'Devices' },
      { key: 'lastSeen', header: 'Last seen' },
      { key: 'createdByEmail', header: 'Added by' },
      { key: 'createdAt', header: 'Created at' },
      { key: 'noticeAcceptedAt', header: 'Notice accepted' },
      { key: 'issues', header: 'Issues' },
      { key: 'userId', header: 'User ID' },
    ],
  };

  function csvColumns(key) {
    return CSV_COLUMNS[key] || [];
  }

  function usageOverviewRows(rows, tz) {
    return (rows || []).map(function (r) {
      r = r || {};
      return {
        userId: escOr(r.userId),
        email: escOr(r.email),
        accountLabel: escOr(r.accountLabel),
        accountUuid: escOr(r.accountUuid),
        organizationUuid: escOr(r.organizationUuid),
        fiveHour: pctOrDash(r.fiveHour),
        sevenDay: pctOrDash(r.sevenDay),
        fiveHourReset: esc(formatTs(r.fiveHourResetsAt, tz)),
        sevenDayReset: esc(formatTs(r.sevenDayResetsAt, tz)),
        updated: esc(formatTs(r.updatedAt, tz)),
      };
    });
  }

  // ---------------------------------------------------------------------
  // verifyModel(auditVerify, permVerify) — GET /admin/audit/verify and
  // GET /admin/permission-changes/verify, each {ok:true,count,headSeq,
  // headHash} or {ok:false,reason,...context}.
  // Returns: {audit:{ok,count,headSeq,headHash,summary}|{ok:false,reason,summary}, permissions: same shape}
  // ---------------------------------------------------------------------

  function verifyItem(v) {
    v = v || {};
    if (v.ok) {
      var count = v.count == null ? 0 : v.count;
      var headSeq = v.headSeq == null ? 0 : v.headSeq;
      return {
        ok: true,
        count: count,
        headSeq: headSeq,
        headHash: escOr(v.headHash),
        summary: esc('Verified — ' + count + ' event' + (count === 1 ? '' : 's') + ', head seq ' + headSeq + '.'),
      };
    }
    var reason = v.reason || 'unknown';
    return {
      ok: false,
      reason: esc(reason),
      summary: esc('Verification FAILED: ' + reason + '.'),
    };
  }

  function verifyModel(auditVerify, permVerify) {
    return {
      audit: verifyItem(auditVerify),
      permissions: verifyItem(permVerify),
    };
  }

  // ---------------------------------------------------------------------
  // effectivePolicyModel(u, tz) — the NET policy for ONE usersDirectory row:
  // what each capability resolves to and WHICH admin control produced it. Pure
  // presentation over the existing knobs (users-doc fields + geo/blocked lists)
  // — it computes nothing new and enforces nothing, it just makes the effect
  // legible. Precedence shown matches what access.js/entitlements.js actually
  // enforce: a block/deny and suspended/deprovisioned/expired access win; an
  // allow-list region lock fails closed; a blocked-country list fails open.
  // Returns { access:{label,tone}, rows:[{name,value,detail,tone}] }, tone in
  // 'ok'|'warn'|'danger'|'muted', every dynamic value pre-escaped.
  // ---------------------------------------------------------------------

  function effectivePolicyModel(u, tz) {
    u = u || {};
    var status = u.status || 'pending';
    var deprov = status === 'deprovisioned';
    var suspended = status === 'suspended';
    var expired = !!u.entitlementExpired;
    var canSignIn = status === 'active' && !expired;

    var access = deprov ? { label: 'No access — deprovisioned', tone: 'danger' }
      : suspended ? { label: 'No access — suspended', tone: 'danger' }
      : expired ? { label: 'No access — entitlement expired', tone: 'danger' }
      : status === 'active' ? { label: 'Active — can sign in', tone: 'ok' }
      : { label: 'Pending — not yet active', tone: 'warn' };

    var fence = Array.isArray(u.geoFenceCountries) ? u.geoFenceCountries : [];
    var blocked = Array.isArray(u.blockedCountries) ? u.blockedCountries : [];
    var mon = u.monitoringEnabled !== false;

    var loc;
    if (blocked.length) loc = { value: 'Restricted', detail: 'Blocked from: ' + esc(blocked.join(', ')) + (fence.length ? '; allowed only in: ' + esc(fence.join(', ')) : ''), tone: 'warn' };
    else if (fence.length) loc = { value: 'Restricted', detail: 'Allowed only in: ' + esc(fence.join(', ')) + ' (locked out elsewhere)', tone: 'warn' };
    else loc = { value: 'Anywhere', detail: 'No location restriction', tone: 'muted' };

    var signInDetail = deprov ? 'Deprovisioned by admin'
      : suspended ? 'Suspended by admin'
      : expired ? ('Entitlement expired' + (u.entitlementExpiresAt ? ' (' + esc(formatTs(u.entitlementExpiresAt, tz)) + ')' : ''))
      : u.entitlementExpiresAt ? ('Access expires ' + esc(formatTs(u.entitlementExpiresAt, tz)))
      : 'No expiry set';

    var rows = [
      { name: 'Sign-in access', value: canSignIn ? 'Allowed' : 'Blocked', detail: signInDetail, tone: canSignIn ? 'ok' : 'danger' },
      { name: 'Import accounts', value: u.importEnabled ? 'Allowed' : 'Blocked', detail: u.importEnabled ? 'Enabled for this user' : 'Not enabled by admin', tone: u.importEnabled ? 'ok' : 'muted' },
      { name: 'Export accounts', value: u.exportEnabled ? 'Allowed' : 'Blocked', detail: u.exportEnabled ? 'Enabled for this user' : 'Not enabled by admin', tone: u.exportEnabled ? 'ok' : 'muted' },
      { name: 'Monitoring', value: mon ? 'On' : 'Paused', detail: mon ? 'Device + activity reporting active' : 'Paused by admin', tone: mon ? 'ok' : 'warn' },
      { name: 'Sign-in location', value: loc.value, detail: loc.detail, tone: loc.tone },
    ];
    return { access: access, rows: rows };
  }

  // ---------------------------------------------------------------------

  var api = {
    esc: esc,
    escAttr: escAttr,
    formatTs: formatTs,
    formatRelative: formatRelative,
    formatGeo: formatGeo,
    overviewModel: overviewModel,
    timelineRows: timelineRows,
    deviceRows: deviceRows,
    userDeviceRows: userDeviceRows,
    ipGeoRows: ipGeoRows,
    alertRows: alertRows,
    traceModel: traceModel,
    transferRows: transferRows,
    userRows: userRows,
    usageOverviewRows: usageOverviewRows,
    toCsv: toCsv,
    csvColumns: csvColumns,
    effectivePolicyModel: effectivePolicyModel,
    verifyModel: verifyModel,
  };

  global.AdminViews = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : this);
