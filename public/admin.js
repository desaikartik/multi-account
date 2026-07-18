'use strict';
// Admin web console UI glue (Phase 5, Task 7). Classic script, loaded after
// /console/adminviews.js (window.AdminViews). Strictly view-only: every
// fetch here targets either the three public auth endpoints or a read-only
// report/verify endpoint on the view-scope allowlist — see PATHS below. No
// mutation affordance exists anywhere in this file by design (Addendum B#6).
//
// Token storage: sessionStorage ONLY (cleared when the tab closes). The only
// two localStorage keys this file ever touches are 'cas-theme' (shared with
// the root web UI) and 'cas-web-device' (a non-secret, stable browser id).
// No report data is persisted anywhere client-side.
(function () {
  var AV = window.AdminViews;
  var $ = function (id) { return document.getElementById(id); };

  // ---------------------------------------------------------------------
  // The exact view-scope allowlist (10 GET report/verify routes) plus the
  // three public auth endpoints. Every API call in this file goes through
  // one of these constants — nothing else is ever fetched.
  // ---------------------------------------------------------------------
  var PATHS = {
    webLogin: '/auth/web-login',
    refresh: '/auth/refresh',
    logout: '/auth/logout',
    timeline: '/admin/reports/timeline',
    devices: '/admin/reports/devices',
    alerts: '/admin/reports/alerts',
    users: '/admin/reports/users',
    usage: '/admin/reports/usage',
    storage: '/admin/reports/storage',
    transfers: '/admin/reports/transfers',
    trace: '/watermarks/trace',
    auditVerify: '/admin/audit/verify',
    permVerify: '/admin/permission-changes/verify',
    auditExport: '/admin/audit/export',
    ipRules: '/admin/ip-rules',
    approveUser: '/admin/users/approve',
    rejectUser: '/admin/users/reject',
  };

  var SS_ACCESS = 'cas-web-access';
  var SS_REFRESH = 'cas-web-refresh';
  var SS_EMAIL = 'cas-web-email';

  var currentView = 'overview';
  var VIEW_TITLES = {
    overview: 'Overview', users: 'Users', usage: 'Usage', timeline: 'Timeline', devices: 'Devices', ipgeo: 'IP & Geo',
    alerts: 'Alerts', transfers: 'Transfers', tracer: 'Tracer', integrity: 'Integrity',
  };

  // ---------------------------------------------------------------------
  // Device id — not a secret, stable per browser (Task 1 decision). The
  // 'cas-web-device' literal is written inline at every call site (rather
  // than through a shared constant) so both allowed keys ('cas-theme' is
  // the other) stay trivially greppable/auditable directly in the source.
  // ---------------------------------------------------------------------
  function getDeviceId() {
    var id = localStorage.getItem('cas-web-device');
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem('cas-web-device', id);
    }
    return id;
  }

  // ---------------------------------------------------------------------
  // Theme (shared key 'cas-theme' with the root web UI).
  // ---------------------------------------------------------------------
  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('cas-theme', theme);
    var btn = $('themeBtn');
    if (btn) {
      btn.textContent = theme === 'dark' ? '☀' : '🌙';
      btn.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
    }
  }
  function toggleTheme() {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  }

  // ---------------------------------------------------------------------
  // Toasts — plain textContent, never innerHTML, so no escaping is needed
  // for server-supplied error text.
  // ---------------------------------------------------------------------
  function toast(msg, isError) {
    var el = document.createElement('div');
    el.className = 'toast' + (isError ? ' error' : '');
    el.textContent = msg;
    $('toasts').appendChild(el);
    setTimeout(function () { el.remove(); }, 4500);
  }

  // ---------------------------------------------------------------------
  // sessionStorage helpers — tokens live ONLY here, cleared when the tab
  // closes. Tokens never touch localStorage (only cas-theme/cas-web-device
  // may — see getDeviceId/applyTheme above) and never touch cookies.
  // ---------------------------------------------------------------------
  function storeTokens(data) {
    sessionStorage.setItem(SS_ACCESS, data.accessToken);
    sessionStorage.setItem(SS_REFRESH, data.refreshToken);
  }
  function getAccessToken() { return sessionStorage.getItem(SS_ACCESS); }
  function getRefreshToken() { return sessionStorage.getItem(SS_REFRESH); }
  function clearSession() {
    sessionStorage.removeItem(SS_ACCESS);
    sessionStorage.removeItem(SS_REFRESH);
    sessionStorage.removeItem(SS_EMAIL);
  }

  // ---------------------------------------------------------------------
  // Fetch wrapper. rawRequest() never throws on a non-2xx response — it
  // hands back {res, data} so callers decide how to react (needed for the
  // refresh-once-on-401 dance). api() is the authenticated helper used by
  // every view loader: same-origin path, Authorization: Bearer, one
  // automatic refresh attempt on a 401, then a single retry; a still-401
  // after that clears the session and returns to the login screen.
  // ---------------------------------------------------------------------
  async function rawRequest(path, opts) {
    opts = opts || {};
    var headers = {};
    var body;
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.body);
    }
    if (opts.auth) {
      var access = getAccessToken();
      if (access) headers.Authorization = 'Bearer ' + access;
    }
    var res = await fetch(path, { method: opts.method || 'GET', headers: headers, body: body });
    var data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    return { res: res, data: data };
  }

  async function doTokenRefresh() {
    var refreshToken = getRefreshToken();
    if (!refreshToken) throw new Error('No refresh token available.');
    var out = await rawRequest(PATHS.refresh, {
      method: 'POST',
      body: { refreshToken: refreshToken, deviceId: getDeviceId() },
    });
    if (!out.res.ok || !out.data || !out.data.accessToken) {
      throw new Error((out.data && out.data.error) || 'Session refresh failed.');
    }
    storeTokens(out.data);
    return out.data;
  }

  function sessionExpired() {
    clearSession();
    showLogin();
    toast('Your session has ended. Please sign in again.', true);
  }

  async function api(path, opts) {
    opts = Object.assign({ auth: true }, opts || {});
    var first = await rawRequest(path, opts);
    if (first.res.status === 401) {
      try {
        await doTokenRefresh();
      } catch (e) {
        sessionExpired();
        throw new Error('Your session has ended. Please sign in again.');
      }
      var second = await rawRequest(path, opts);
      if (second.res.status === 401) {
        sessionExpired();
        throw new Error('Your session has ended. Please sign in again.');
      }
      if (!second.res.ok) throw new Error((second.data && second.data.error) || 'Something went wrong. Please try again.');
      return second.data;
    }
    if (!first.res.ok) throw new Error((first.data && first.data.error) || 'Something went wrong. Please try again.');
    return first.data;
  }

  function buildQuery(params) {
    var usp = new URLSearchParams();
    if (params) {
      Object.keys(params).forEach(function (k) {
        var v = params[k];
        if (v !== undefined && v !== null && v !== '') usp.set(k, String(v));
      });
    }
    var s = usp.toString();
    return s ? ('?' + s) : '';
  }
  function apiGet(base, params) { return api(base + buildQuery(params)); }

  // ---------------------------------------------------------------------
  // Screen / view routing.
  // ---------------------------------------------------------------------
  function showLogin() {
    $('screen-app').classList.add('hidden');
    $('screen-login').classList.remove('hidden');
  }
  function showApp() {
    $('screen-login').classList.add('hidden');
    $('screen-app').classList.remove('hidden');
  }

  function showView(view) {
    currentView = view;
    Object.keys(VIEW_TITLES).forEach(function (v) {
      var el = $('view-' + v);
      if (el) el.classList.toggle('hidden', v !== view);
    });
    document.querySelectorAll('.nav-item').forEach(function (n) {
      n.classList.toggle('active', n.dataset.view === view);
    });
    $('pageTitle').textContent = VIEW_TITLES[view];
    loadView(view);
  }

  function loadView(view) {
    if (view === 'overview') loadOverview();
    else if (view === 'users') loadUsers();
    else if (view === 'usage') loadUsage();
    else if (view === 'timeline') loadTimeline();
    else if (view === 'devices') loadDevices();
    else if (view === 'ipgeo') loadIpGeo();
    else if (view === 'alerts') loadAlerts();
    else if (view === 'transfers') loadTransfers();
    else if (view === 'integrity') loadIntegrity();
    // 'tracer' has no data to load until the admin enters a watermark id.
  }

  // ---------------------------------------------------------------------
  // CSP-safe dynamic widths: a `style=""` attribute is never written into
  // markup; instead a data-w percentage rides through innerHTML and this
  // helper applies it via the CSSOM `.style` property afterwards (allowed
  // under the strict style-src 'self' policy — see desktop/src/renderer/
  // app.js's applyDynStyles for the same technique).
  // ---------------------------------------------------------------------
  function applyDynWidths(root) {
    root.querySelectorAll('[data-w]').forEach(function (el) {
      el.style.width = Math.max(0, Math.min(100, Number(el.dataset.w) || 0)) + '%';
      el.removeAttribute('data-w');
    });
  }

  function fmtBytes(n) {
    if (n == null || isNaN(n)) return '—';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var v = Number(n);
    var i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? String(v) : v.toFixed(1)) + ' ' + units[i];
  }

  function emptyRow(colspan) {
    return '<tr><td class="empty-row" colspan="' + colspan + '">No data to show.</td></tr>';
  }

  function kpiTile(label, value, sub, opts) {
    opts = opts || {};
    var meter = opts.pct != null
      ? '<span class="k-meter"><span class="k-fill" data-w="' + Math.max(0, Math.min(100, opts.pct)) + '"></span></span>'
      : '';
    return '<div class="kpi ' + (opts.cls || '') + '">' +
      '<div class="k-label">' + AV.esc(label) + '</div>' +
      '<div class="k-value">' + AV.esc(value) + '</div>' +
      '<div class="k-sub">' + AV.esc(sub || '') + '</div>' + meter +
      '</div>';
  }

  // ---------------------------------------------------------------------
  // Overview
  // ---------------------------------------------------------------------
  async function loadOverview() {
    try {
      var results = await Promise.all([apiGet(PATHS.devices), apiGet(PATHS.storage), apiGet(PATHS.timeline)]);
      var devicesData = results[0];
      var storageData = results[1];
      var timelineData = results[2];
      var model = AV.overviewModel({
        devices: devicesData.devices, storage: storageData, timeline: timelineData, nowMs: Date.now(),
      });
      renderOverview(model);
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderOverview(model) {
    var pct = model.storagePercent == null ? null : Math.round(model.storagePercent);
    var pctCls = pct == null ? '' : pct >= 90 ? 'danger' : pct >= 70 ? 'warn' : '';
    var windowLabel = model.windowDays != null
      ? ('last ' + model.windowDays + ' day' + (model.windowDays === 1 ? '' : 's'))
      : '';
    var storageSub = (model.storageEstimatedBytes != null && model.storageCapacityBytes != null)
      ? (fmtBytes(model.storageEstimatedBytes) + ' of ' + fmtBytes(model.storageCapacityBytes))
      : '';
    var html =
      kpiTile('Active users', model.activeUsers, windowLabel) +
      kpiTile('Active devices (24h)', model.activeDevices, model.totalDevices + ' total device' + (model.totalDevices === 1 ? '' : 's')) +
      kpiTile('Storage used', pct == null ? '—' : pct + '%', storageSub, { pct: pct, cls: pctCls });
    var el = $('overviewKpis');
    el.innerHTML = html;
    applyDynWidths(el);
  }

  // ---------------------------------------------------------------------
  // Users — every user by email, with status/entitlements/devices/alerts and
  // an ISSUES column; rows with issues are highlighted (row-alert) so an
  // admin instantly sees which user has which problem. View-only: no
  // mutation affordance here (that lives in the desktop app's Controls tab).
  // ---------------------------------------------------------------------
  // Last-loaded RAW report payloads, kept so "Export CSV" serializes the full
  // population that is already on screen (never a re-fetch, never a top-N).
  var lastRaw = {};

  async function loadUsers() {
    try {
      var data = await apiGet(PATHS.users);
      lastRaw.users = data.users;
      renderUsers(AV.userRows(data.users));
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderUsers(rows) {
    $('usersBody').innerHTML = rows.length ? rows.map(function (u) {
      var actions = '';
      if (u.pendingApproval) {
        actions = '<button class="btn small" data-action="approve-user" data-id="' + u.userId + '" type="button">Approve</button>' +
          '<button class="btn small danger" data-action="reject-user" data-id="' + u.userId + '" type="button">Reject</button>';
      } else if (u.rejected) {
        actions = '<button class="btn small" data-action="approve-user" data-id="' + u.userId + '" type="button">Approve</button>';
      }
      return '<tr class="' + (u.hasIssues ? 'row-alert' : '') + '"><td>' + u.email + '</td><td>' + u.createdByEmail + '</td><td>' + u.role +
        '</td><td>' + u.status + '</td><td>' + u.importEnabled + '</td><td>' + u.exportEnabled +
        '</td><td>' + u.monitoring + '</td><td>' + u.expires + '</td><td>' + u.devices +
        '</td><td>' + u.alerts + '</td><td>' + u.issues + '</td><td class="row-actions">' + actions + '</td></tr>';
    }).join('') : emptyRow(12);
  }

  async function doApproveUser(userId) {
    if (!userId) return;
    try {
      await api(PATHS.approveUser, { method: 'POST', body: { targetUserId: userId } });
      toast('User approved.');
      loadUsers();
    } catch (err) { toast(err.message, true); }
  }

  async function doRejectUser(userId) {
    if (!userId) return;
    if (!window.confirm('Reject this signup? They will not be able to sign in (you can approve them later).')) return;
    try {
      await api(PATHS.rejectUser, { method: 'POST', body: { targetUserId: userId } });
      toast('Signup rejected.');
      loadUsers();
    } catch (err) { toast(err.message, true); }
  }

  // ---------------------------------------------------------------------
  // Usage — fleet "Usage overview" (f1a-usage-backend, GET /admin/reports/usage):
  // who has used how much of each Claude account's limit, and when. View-only,
  // same day-window pattern as Timeline/Alerts/Transfers below; rows come
  // pre-formatted from the shared AV.usageOverviewRows builder (byte-identical
  // with the desktop admin Usage tab).
  // ---------------------------------------------------------------------
  async function loadUsage() {
    var days = $('usageDays').value;
    try {
      var data = await apiGet(PATHS.usage, { days: days });
      lastRaw.usage = data.rows;
      renderUsage(AV.usageOverviewRows(data.rows));
      $('usageWindow').textContent = 'Showing the last ' + data.windowDays + ' day' + (data.windowDays === 1 ? '' : 's') + '.';
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderUsage(rows) {
    $('usageBody').innerHTML = rows.length ? rows.map(function (r) {
      return '<tr><td>' + r.email + '</td><td>' + r.accountLabel + '</td><td>' + r.fiveHour +
        '</td><td>' + r.fiveHourReset + '</td><td>' + r.sevenDay + '</td><td>' + r.sevenDayReset +
        '</td><td>' + r.updated + '</td></tr>';
    }).join('') : emptyRow(7);
  }

  // ---------------------------------------------------------------------
  // Timeline
  // ---------------------------------------------------------------------
  async function loadTimeline() {
    var days = $('timelineDays').value;
    var userId = $('timelineUserId').value.trim();
    try {
      var data = await apiGet(PATHS.timeline, { days: days, userId: userId || undefined });
      var rows = AV.timelineRows(data.events);
      renderTimeline(rows);
      $('timelineWindow').textContent = 'Showing the last ' + data.windowDays + ' day' + (data.windowDays === 1 ? '' : 's') + '.';
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderTimeline(rows) {
    $('timelineBody').innerHTML = rows.length ? rows.map(function (r) {
      return '<tr><td>' + (r.seq == null ? '—' : r.seq) + '</td><td>' + r.time + '</td><td>' + r.eventType +
        '</td><td>' + r.severity + '</td><td>' + (r.email !== '—' ? r.email : r.userId) + '</td><td>' + r.deviceId + '</td><td>' + r.result +
        '</td><td>' + r.reason + '</td><td>' + r.geo + '</td><td>' + r.ip + '</td></tr>';
    }).join('') : emptyRow(10);
  }

  // ---------------------------------------------------------------------
  // Devices
  // ---------------------------------------------------------------------
  async function loadDevices() {
    try {
      var data = await apiGet(PATHS.devices);
      var rows = AV.deviceRows(data.devices);
      renderDevices(rows);
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderDevices(rows) {
    $('devicesBody').innerHTML = rows.length ? rows.map(function (d) {
      return '<tr><td>' + d.deviceId + '</td><td>' + (d.email !== '—' ? d.email : d.userId) + '</td><td>' + d.status + '</td><td>' + d.firstSeen +
        '</td><td>' + d.lastSeen + '</td><td>' + d.appVersion + '</td><td>' + d.os + '</td><td>' + d.ipv4 +
        '</td><td>' + d.geo4 + '</td><td>' + d.ipv6 + '</td><td>' + d.geo6 + '</td><td>' + d.lastIp + '</td><td>' + d.geo + '</td></tr>';
    }).join('') : emptyRow(13);
  }

  // ---------------------------------------------------------------------
  // IP & Geo — per-device IPs/geo (ipGeoRows) plus the currently configured
  // IP allow/block rules (raw docs; read-only display only, no editor —
  // rule mutation is a desktop-only, authenticated-endpoint action).
  // ---------------------------------------------------------------------
  async function loadIpGeo() {
    try {
      var devicesData = await apiGet(PATHS.devices);
      renderIpGeo(AV.ipGeoRows(devicesData.devices));
    } catch (err) {
      toast(err.message, true);
    }
    try {
      var rulesData = await apiGet(PATHS.ipRules);
      renderIpRules(rulesData.rules || []);
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderIpGeo(rows) {
    $('ipgeoBody').innerHTML = rows.length ? rows.map(function (d) {
      return '<tr><td>' + d.deviceId + '</td><td>' + (d.email !== '—' ? d.email : d.userId) + '</td><td>' + d.lastSeen + '</td><td>' + d.ipv4 +
        '</td><td>' + d.geo4 + '</td><td>' + d.ipv6 + '</td><td>' + d.geo6 + '</td></tr>';
    }).join('') : emptyRow(7);
  }

  // Raw ip_rules docs have no adminviews.js builder (view-only console has
  // no mutation UI for them), so fields are escaped here directly with the
  // shared esc()/formatTs() primitives instead of a pre-escaped row builder.
  function renderIpRules(rules) {
    $('ipRulesBody').innerHTML = rules.length ? rules.map(function (r) {
      return '<tr><td>' + AV.esc(r.scope) + '</td><td>' + (r.userId ? AV.esc(r.userId) : '—') +
        '</td><td>' + AV.esc(r.type) + '</td><td>' + AV.esc(r.cidr) + '</td><td>' + (r.reason ? AV.esc(r.reason) : '—') +
        '</td><td>' + (r.createdBy ? AV.esc(r.createdBy) : '—') + '</td><td>' + AV.esc(AV.formatTs(r.createdAt)) + '</td></tr>';
    }).join('') : emptyRow(7);
  }

  // ---------------------------------------------------------------------
  // Alerts
  // ---------------------------------------------------------------------
  async function loadAlerts() {
    var days = $('alertsDays').value;
    try {
      var data = await apiGet(PATHS.alerts, { days: days });
      var rows = AV.alertRows(data.alerts);
      renderAlerts(rows);
      $('alertsWindow').textContent = 'Showing the last ' + data.windowDays + ' day' + (data.windowDays === 1 ? '' : 's') + '.';
    } catch (err) {
      toast(err.message, true);
    }
  }

  // Reason cell shows the friendly reasonLabel (server-joined, E3) with the
  // raw reason code as a title/secondary (both already pre-escaped by
  // AV.alertRows, so a title="" attribute is safe here).
  function renderAlerts(rows) {
    $('alertsBody').innerHTML = rows.length ? rows.map(function (a) {
      var muted = a.alertsMuted ? ' <span class="muted-badge">alerts off</span>' : '';
      return '<tr class="' + (a.severity === 'critical' ? 'row-alert' : '') + '"><td>' + (a.seq == null ? '—' : a.seq) + '</td><td>' + a.time +
        '</td><td><span class="sev sev-' + a.severity + '">' + a.severity + '</span></td><td>' + a.eventType + '</td><td title="' + a.reason + '">' + a.reasonLabel +
        '</td><td>' + a.email + muted + '</td><td>' + a.userId + '</td><td>' + a.deviceId + '</td></tr>';
    }).join('') : emptyRow(8);
  }

  // ---------------------------------------------------------------------
  // Transfers
  // ---------------------------------------------------------------------
  async function loadTransfers() {
    var days = $('transfersDays').value;
    try {
      var data = await apiGet(PATHS.transfers, { days: days });
      var rows = AV.transferRows(data.transfers);
      renderTransfers(rows);
      $('transfersWindow').textContent = 'Cross-user rows (import by someone other than the exporter) are highlighted.';
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderTransfers(rows) {
    $('transfersBody').innerHTML = rows.length ? rows.map(function (t) {
      var badge = t.badge ? '<span class="badge cross-user">' + t.badge + '</span>' : '';
      var importsHtml = t.imports.length
        ? t.imports.map(function (i) { return '<div class="flow-imp' + (i.crossUser ? ' cross' : '') + '">' + i.email + ' · ' + i.at + (i.ip !== '—' ? ' · ' + i.ip : '') + '</div>'; }).join('')
        : '<span class="sub">Not imported yet</span>';
      return '<tr class="' + (t.crossUser ? 'row-alert' : '') + '"><td>' + t.exportEmail + '</td><td>' + t.exportDeviceId +
        '</td><td>' + t.exportedAt + '</td><td>' + importsHtml + '</td><td>' + badge + '</td></tr>';
    }).join('') : emptyRow(5);
  }

  // ---------------------------------------------------------------------
  // Tracer
  // ---------------------------------------------------------------------
  async function doTrace() {
    var id = $('tracerInput').value.trim();
    if (!id) { toast('Enter a watermark id to trace.', true); return; }
    try {
      var data = await apiGet(PATHS.trace, { watermarkId: id });
      renderTrace(AV.traceModel(data));
    } catch (err) {
      toast(err.message, true);
    }
  }

  function renderTrace(model) {
    var warn = model.crossUser
      ? '<div class="notice warn show"><div class="title">Cross-user import detected</div><div>One or more imports on this watermark were performed by a different user than the exporter.</div></div>'
      : '';
    var exp = model.export;
    var importsHtml = model.imports.length ? model.imports.map(function (i) {
      var badge = i.crossUser ? '<span class="badge cross-user">cross-user</span>' : '';
      return '<tr class="' + (i.crossUser ? 'row-alert' : '') + '"><td>' + i.userId + '</td><td>' + i.deviceId +
        '</td><td>' + i.at + '</td><td>' + i.ip + '</td><td>' + badge + '</td></tr>';
    }).join('') : emptyRow(5);

    $('tracerResult').innerHTML = warn +
      '<div class="panel">' +
      '<h3>Export</h3>' +
      '<p><b>Watermark:</b> ' + model.watermarkId + '</p>' +
      '<p><b>User:</b> ' + exp.userId + ' &nbsp; <b>Device:</b> ' + exp.deviceId + '</p>' +
      '<p><b>Exported at:</b> ' + exp.exportedAt + '</p>' +
      '<p><b>File SHA-256:</b> ' + exp.fileSha256 + '</p>' +
      '</div>' +
      '<div class="section-head"><h2>Imports <span class="count">(' + model.importCount + ')</span></h2></div>' +
      '<div class="table-wrap"><table><thead><tr><th>User</th><th>Device</th><th>At</th><th>IP</th><th></th></tr></thead>' +
      '<tbody>' + importsHtml + '</tbody></table></div>';
  }

  // ---------------------------------------------------------------------
  // Integrity
  // ---------------------------------------------------------------------
  async function loadIntegrity() {
    var auditData = { ok: false, reason: 'request failed' };
    var permData = { ok: false, reason: 'request failed' };
    try { auditData = await apiGet(PATHS.auditVerify); } catch (err) { toast(err.message, true); }
    try { permData = await apiGet(PATHS.permVerify); } catch (err) { toast(err.message, true); }
    renderIntegrity(AV.verifyModel(auditData, permData));
  }

  function verifyChipHtml(item) {
    var cls = item.ok ? 'chip ok' : 'chip danger';
    var label = item.ok ? 'Verified' : 'Failed';
    return '<span class="' + cls + '">' + label + '</span><p class="verify-summary">' + item.summary + '</p>';
  }

  function renderIntegrity(model) {
    $('auditVerifyChip').innerHTML = verifyChipHtml(model.audit);
    $('permVerifyChip').innerHTML = verifyChipHtml(model.permissions);
  }

  async function doDownloadExport() {
    try {
      var data = await api(PATHS.auditExport);
      var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'audit-export-' + Date.now() + '.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast('Audit export downloaded.');
    } catch (err) {
      toast(err.message, true);
    }
  }

  // ---------------------------------------------------------------------
  // Login / sign-out
  // ---------------------------------------------------------------------
  function setLoginMsg(text, kind) {
    var el = $('loginMsg');
    el.textContent = text || '';
    el.className = 'form-msg' + (kind ? ' ' + kind : '');
  }

  async function handleLoginSubmit(e) {
    e.preventDefault();
    var email = $('loginEmail').value.trim();
    var password = $('loginPassword').value;
    setLoginMsg('Signing in…');
    try {
      var out = await rawRequest(PATHS.webLogin, {
        method: 'POST', body: { email: email, password: password, deviceId: getDeviceId() },
      });
      if (!out.res.ok) throw new Error((out.data && out.data.error) || 'Sign-in failed. Please try again.');
      storeTokens(out.data);
      sessionStorage.setItem(SS_EMAIL, email);
      $('loginPassword').value = '';
      setLoginMsg('');
      $('adminEmail').textContent = email;
      showApp();
      showView('overview');
    } catch (err) {
      setLoginMsg(err.message || 'Sign-in failed. Please try again.', 'error');
    }
  }

  async function doSignOut() {
    var refreshToken = getRefreshToken();
    try {
      if (refreshToken) await rawRequest(PATHS.logout, { method: 'POST', body: { refreshToken: refreshToken } });
    } catch (e) { /* best-effort — the session is being cleared locally regardless */ }
    clearSession();
    showLogin();
  }

  function downloadBlob(name, content, type) {
    var blob = new Blob([content], { type: type });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // Client-side CSV of a report's already-fetched FULL raw population
  // (no server round-trip, no top-N truncation) — from lastRaw[report].
  function doDownloadCsv(report) {
    var rows = lastRaw[report];
    if (!rows || !rows.length) { toast('Load the report first, then export.', true); return; }
    var csv = AV.toCsv(rows, AV.csvColumns(report));
    downloadBlob(report + '-export-' + Date.now() + '.csv', csv, 'text/csv;charset=utf-8;');
    toast('CSV downloaded (' + rows.length + ' row' + (rows.length === 1 ? '' : 's') + ').');
  }

  // ---------------------------------------------------------------------
  // Event wiring — everything delegated, no inline handlers anywhere (CSP).
  // ---------------------------------------------------------------------
  document.addEventListener('click', function (e) {
    var nav = e.target.closest('.nav-item');
    if (nav) { showView(nav.dataset.view); return; }
    var btn = e.target.closest('[data-action]');
    if (!btn) return;
    switch (btn.dataset.action) {
      case 'theme': toggleTheme(); break;
      case 'signout': doSignOut(); break;
      case 'refresh-overview': loadOverview(); break;
      case 'refresh-users': loadUsers(); break;
      case 'approve-user': doApproveUser(btn.dataset.id); break;
      case 'reject-user': doRejectUser(btn.dataset.id); break;
      case 'refresh-usage': loadUsage(); break;
      case 'refresh-timeline': loadTimeline(); break;
      case 'refresh-devices': loadDevices(); break;
      case 'refresh-ipgeo': loadIpGeo(); break;
      case 'refresh-alerts': loadAlerts(); break;
      case 'refresh-transfers': loadTransfers(); break;
      case 'trace-search': doTrace(); break;
      case 'refresh-integrity': loadIntegrity(); break;
      case 'download-export': doDownloadExport(); break;
      case 'download-csv': doDownloadCsv(btn.dataset.report); break;
      case 'print-view': window.print(); break;
      default: break;
    }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return;
    if (e.target && e.target.id === 'tracerInput') doTrace();
    if (e.target && e.target.id === 'timelineUserId') loadTimeline();
  });

  $('loginForm').addEventListener('submit', handleLoginSubmit);

  // ---------------------------------------------------------------------
  // Boot: tokens live only in sessionStorage, so a same-tab reload resumes
  // the session; a fresh tab always starts at the login screen.
  // ---------------------------------------------------------------------
  applyTheme(localStorage.getItem('cas-theme') || 'light');
  if (getAccessToken()) {
    $('adminEmail').textContent = sessionStorage.getItem(SS_EMAIL) || '';
    showApp();
    showView('overview');
  } else {
    showLogin();
  }
})();
