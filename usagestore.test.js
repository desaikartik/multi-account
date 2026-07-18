'use strict';
// Usage tracking store — pure DI, additive, NOT the audit ledger (spec:
// f1a-usage-backend). Mirrors the offline/DI test conventions of
// backend.test.js: in-memory repo, fixed injected clock, real field-crypto.
//
// Run: cd backend && node --test

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { makeClock } = require('./lib/clock');
const { generateKeys, loadConfig } = require('./lib/config');
const { createMemoryRepo } = require('./lib/repo');
const { createFieldCrypto } = require('./lib/crypto');
const usagestore = require('./lib/usagestore');
const { clampPct, mergeSeries, recordUsageSnapshot, myUsage } = usagestore;

function fullEnv(overrides = {}) {
  return {
    ...generateKeys(),
    MONGODB_URI: 'mongodb+srv://u:p@localhost/?tls=true',
    MONGODB_DB: 'switcher_test',
    GMAIL_USER: 'ops@example.com',
    GMAIL_APP_PASSWORD: 'aaaa bbbb cccc dddd',
    PORT: '8787',
    ...overrides,
  };
}

function makeCtx(overrides = {}) {
  const config = loadConfig(fullEnv());
  const clock = makeClock(1_700_000_000_000); // fixed epoch, mid-hour-ish
  const repo = createMemoryRepo();
  const crypto = createFieldCrypto(config.fieldEncKey, config.blindIndexKey);
  const logger = { info() {}, error() {} };
  return { config, clock, repo, crypto, logger, ...overrides };
}

// ===========================================================================
// clampPct(v)
// ===========================================================================

test('clampPct: null and undefined pass through as null', () => {
  assert.equal(clampPct(null), null);
  assert.equal(clampPct(undefined), null);
});

test('clampPct: clamps above 100 down to 100', () => {
  assert.equal(clampPct(150), 100);
  assert.equal(clampPct(100), 100);
  assert.equal(clampPct(100.5), 100);
});

test('clampPct: clamps below 0 up to 0', () => {
  assert.equal(clampPct(-5), 0);
  assert.equal(clampPct(0), 0);
});

test('clampPct: a mid-range number passes through unchanged', () => {
  assert.equal(clampPct(42), 42);
  assert.equal(clampPct(0.5), 0.5);
});

test('clampPct: a non-numeric value maps to null', () => {
  assert.equal(clampPct('x'), null);
  assert.equal(clampPct({}), null);
  assert.equal(clampPct([1, 2]), null);
  assert.equal(clampPct(NaN), null);
  assert.equal(clampPct(Infinity), null);
});

test('clampPct: a numeric string is coerced then clamped', () => {
  assert.equal(clampPct('55'), 55);
  assert.equal(clampPct('200'), 100);
});

// ===========================================================================
// mergeSeries(prevSeries, point, nowMs, {cap, bucketMs})
// ===========================================================================

const HOUR = 3600000;

test('mergeSeries: empty prevSeries → pushes the point as the only entry', () => {
  const out = mergeSeries([], { t: 1000, s5: 10, s7: 20 }, 1000, { cap: 168, bucketMs: HOUR });
  assert.deepEqual(out, [{ t: 1000, s5: 10, s7: 20 }]);
});

test('mergeSeries: nowMs in the SAME hour-bucket as the last point → replaces the last point', () => {
  const t0 = 10 * HOUR; // bucket 10
  const prev = [{ t: t0, s5: 10, s7: 20 }];
  const nowMs = t0 + 1500; // still bucket 10
  const out = mergeSeries(prev, { t: nowMs, s5: 15, s7: 25 }, nowMs, { cap: 168, bucketMs: HOUR });
  assert.equal(out.length, 1, 'same-hour point replaces, does not append');
  assert.deepEqual(out[0], { t: nowMs, s5: 15, s7: 25 });
});

test('mergeSeries: nowMs in a NEW hour-bucket → appends a new point, keeps the old one', () => {
  const t0 = 10 * HOUR;
  const prev = [{ t: t0, s5: 10, s7: 20 }];
  const nowMs = 11 * HOUR + 5; // bucket 11
  const out = mergeSeries(prev, { t: nowMs, s5: 15, s7: 25 }, nowMs, { cap: 168, bucketMs: HOUR });
  assert.equal(out.length, 2);
  assert.deepEqual(out[0], { t: t0, s5: 10, s7: 20 });
  assert.deepEqual(out[1], { t: nowMs, s5: 15, s7: 25 });
});

test('mergeSeries: trims to cap, keeping the NEWEST points (oldest dropped)', () => {
  let series = [];
  let nowMs = 0;
  for (let i = 0; i < 5; i++) {
    nowMs = i * HOUR;
    series = mergeSeries(series, { t: nowMs, s5: i, s7: i * 2 }, nowMs, { cap: 3, bucketMs: HOUR });
  }
  assert.equal(series.length, 3, 'trimmed to cap');
  // Points for i=0,1 dropped; i=2,3,4 retained (newest-first ordering preserved as append order).
  assert.deepEqual(series.map(p => p.s5), [2, 3, 4]);
});

test('mergeSeries: null s5/s7 on the point are preserved verbatim (not coerced to 0)', () => {
  const out = mergeSeries([], { t: 1000, s5: null, s7: null }, 1000, { cap: 168, bucketMs: HOUR });
  assert.deepEqual(out, [{ t: 1000, s5: null, s7: null }]);
});

test('mergeSeries: is pure — does not mutate the prevSeries array or its objects', () => {
  const t0 = 5 * HOUR;
  const prev = [{ t: t0, s5: 1, s7: 2 }];
  const prevCopy = JSON.parse(JSON.stringify(prev));
  mergeSeries(prev, { t: t0 + 10, s5: 99, s7: 99 }, t0 + 10, { cap: 168, bucketMs: HOUR });
  assert.deepEqual(prev, prevCopy, 'prevSeries must be unchanged by the call');
});

// ===========================================================================
// recordUsageSnapshot(ctx, {userId, accounts})
// ===========================================================================

function sampleAccount(overrides = {}) {
  return {
    accountUuid: 'acct-1',
    organizationUuid: 'org-1',
    label: 'work@example.com',
    fiveHour: 30,
    sevenDay: 45,
    fiveHourResetsAt: '2026-07-17T12:00:00.000Z',
    sevenDayResetsAt: '2026-07-20T00:00:00.000Z',
    capturedAt: '2026-07-17T10:00:00.000Z',
    ...overrides,
  };
}

test('recordUsageSnapshot: creates a doc with encrypted labelEnc + stamped userId/updatedAt/firstSeen', async () => {
  const ctx = makeCtx();
  await recordUsageSnapshot(ctx, { userId: 'user-1', accounts: [sampleAccount()] });

  const doc = await ctx.repo.usageSnapshots.findById('user-1|acct-1::org-1');
  assert.ok(doc, 'deterministic _id doc exists');
  assert.equal(doc.userId, 'user-1');
  assert.equal(doc.accountUuid, 'acct-1');
  assert.equal(doc.organizationUuid, 'org-1');
  assert.notEqual(doc.labelEnc, 'work@example.com', 'label is encrypted at rest');
  assert.equal(doc.fiveHour, 30);
  assert.equal(doc.sevenDay, 45);
  assert.equal(doc.updatedAt.getTime(), ctx.clock.nowMs());
  assert.equal(doc.firstSeen.getTime(), ctx.clock.nowMs());
  assert.equal(doc.series.length, 1);
  assert.equal(doc.series[0].s5, 30);
  assert.equal(doc.series[0].s7, 45);

  const label = ctx.crypto.decrypt(doc.labelEnc, 'usage:' + doc._id);
  assert.equal(label, 'work@example.com');
});

test('recordUsageSnapshot: a second call for the same account updates latest fields + appends to series', async () => {
  const ctx = makeCtx();
  await recordUsageSnapshot(ctx, { userId: 'user-1', accounts: [sampleAccount({ fiveHour: 10, sevenDay: 20 })] });
  const firstDoc = await ctx.repo.usageSnapshots.findById('user-1|acct-1::org-1');

  ctx.clock.advance(2 * HOUR); // force a new hour bucket
  await recordUsageSnapshot(ctx, { userId: 'user-1', accounts: [sampleAccount({ fiveHour: 60, sevenDay: 70 })] });

  const doc = await ctx.repo.usageSnapshots.findById('user-1|acct-1::org-1');
  assert.equal(doc.fiveHour, 60, 'latest fiveHour is updated');
  assert.equal(doc.sevenDay, 70, 'latest sevenDay is updated');
  assert.equal(doc.series.length, 2, 'a new hour bucket appends a second series point');
  assert.equal(doc.firstSeen.getTime(), firstDoc.firstSeen.getTime(), 'firstSeen is preserved across updates');
  assert.equal(doc.updatedAt.getTime(), ctx.clock.nowMs(), 'updatedAt advances to the new call time');
});

test('recordUsageSnapshot: IGNORES a client-supplied userId field inside an account entry', async () => {
  const ctx = makeCtx();
  await recordUsageSnapshot(ctx, {
    userId: 'real-user',
    accounts: [sampleAccount({ userId: 'attacker-spoofed-id' })],
  });
  const doc = await ctx.repo.usageSnapshots.findById('real-user|acct-1::org-1');
  assert.ok(doc);
  assert.equal(doc.userId, 'real-user', 'the stamped userId is from the ctx argument, never the body');

  const spoofed = await ctx.repo.usageSnapshots.findById('attacker-spoofed-id|acct-1::org-1');
  assert.equal(spoofed, null, 'no doc was ever created under the spoofed userId');
});

test('recordUsageSnapshot: caps accounts length at 50 — extras beyond the cap are dropped', async () => {
  const ctx = makeCtx();
  const accounts = [];
  for (let i = 0; i < 60; i++) {
    accounts.push(sampleAccount({ accountUuid: `acct-${i}`, organizationUuid: 'org-1' }));
  }
  const out = await recordUsageSnapshot(ctx, { userId: 'user-1', accounts });
  assert.equal(out.recorded, 50, 'only the first 50 accounts are processed');
  const all = ctx.repo.usageSnapshots._all();
  assert.equal(all.length, 50);
});

test('recordUsageSnapshot: clamps an out-of-range or bad pct value instead of storing it verbatim', async () => {
  const ctx = makeCtx();
  await recordUsageSnapshot(ctx, {
    userId: 'user-1',
    accounts: [sampleAccount({ fiveHour: 500, sevenDay: 'not-a-number' })],
  });
  const doc = await ctx.repo.usageSnapshots.findById('user-1|acct-1::org-1');
  assert.equal(doc.fiveHour, 100, 'clamped to 100');
  assert.equal(doc.sevenDay, null, 'a bad value becomes null, never thrown or stored raw');
});

test('recordUsageSnapshot: null/missing accounts is a no-op, never throws', async () => {
  const ctx = makeCtx();
  const out = await recordUsageSnapshot(ctx, { userId: 'user-1', accounts: undefined });
  assert.equal(out.recorded, 0);
  assert.deepEqual(ctx.repo.usageSnapshots._all(), []);
});

// ===========================================================================
// myUsage(ctx, {userId, days})
// ===========================================================================

test('myUsage: returns only the caller\'s own docs, decrypted, with series', async () => {
  const ctx = makeCtx();
  await recordUsageSnapshot(ctx, { userId: 'alice', accounts: [sampleAccount({ accountUuid: 'a1', label: 'alice@work.com' })] });
  await recordUsageSnapshot(ctx, { userId: 'bob', accounts: [sampleAccount({ accountUuid: 'b1', label: 'bob@work.com' })] });

  const out = await myUsage(ctx, { userId: 'alice', days: 7 });
  assert.equal(out.accounts.length, 1);
  assert.equal(out.accounts[0].accountUuid, 'a1');
  assert.equal(out.accounts[0].label, 'alice@work.com');
  assert.ok(Array.isArray(out.accounts[0].series));
  assert.equal(out.accounts[0].series.length, 1);
});

test('myUsage: a second user with the SAME account label gets zero cross-leak', async () => {
  const ctx = makeCtx();
  await recordUsageSnapshot(ctx, { userId: 'alice', accounts: [sampleAccount({ accountUuid: 'shared-acct', organizationUuid: 'shared-org', label: 'same-label@example.com' })] });
  await recordUsageSnapshot(ctx, { userId: 'bob', accounts: [sampleAccount({ accountUuid: 'shared-acct', organizationUuid: 'shared-org', label: 'same-label@example.com' })] });

  const aliceOut = await myUsage(ctx, { userId: 'alice', days: 7 });
  const bobOut = await myUsage(ctx, { userId: 'bob', days: 7 });
  assert.equal(aliceOut.accounts.length, 1);
  assert.equal(bobOut.accounts.length, 1);
  // Confirm alice never sees bob's doc and vice versa (same accountUuid/org, different owner).
  assert.notEqual(aliceOut.accounts[0], bobOut.accounts[0]);
});

test('myUsage: windowed by days — an update older than the window is excluded', async () => {
  const ctx = makeCtx();
  await recordUsageSnapshot(ctx, { userId: 'alice', accounts: [sampleAccount({ accountUuid: 'old-acct' })] });
  ctx.clock.advance(8 * 24 * HOUR); // 8 days later, outside the 7-day window
  await recordUsageSnapshot(ctx, { userId: 'alice', accounts: [sampleAccount({ accountUuid: 'new-acct' })] });

  const out = await myUsage(ctx, { userId: 'alice', days: 7 });
  const uuids = out.accounts.map(a => a.accountUuid);
  assert.ok(uuids.includes('new-acct'));
  assert.ok(!uuids.includes('old-acct'), 'a doc not updated within the window is excluded');
});

test('myUsage: days is clamped like reporting.clampDays ([1,7]) — a huge window request cannot widen it', async () => {
  const ctx = makeCtx();
  await recordUsageSnapshot(ctx, { userId: 'alice', accounts: [sampleAccount({ accountUuid: 'old-acct' })] });
  ctx.clock.advance(10 * 24 * HOUR); // 10 days later
  await recordUsageSnapshot(ctx, { userId: 'alice', accounts: [sampleAccount({ accountUuid: 'new-acct' })] });

  const out = await myUsage(ctx, { userId: 'alice', days: 3650 });
  const uuids = out.accounts.map(a => a.accountUuid);
  assert.ok(!uuids.includes('old-acct'), 'days is clamped to a max of 7, not honored verbatim');
  assert.equal(out.windowDays, 7);
});

test('myUsage: a label decrypt failure yields null instead of throwing', async () => {
  const ctx = makeCtx();
  await recordUsageSnapshot(ctx, { userId: 'alice', accounts: [sampleAccount({ accountUuid: 'broken-acct' })] });
  await ctx.repo.usageSnapshots.updateById('alice|broken-acct::org-1', { labelEnc: 'not-valid-ciphertext' });

  const out = await myUsage(ctx, { userId: 'alice', days: 7 });
  assert.equal(out.accounts[0].label, null);
});

test('myUsage: an unknown/never-reporting user gets an empty accounts list, not an error', async () => {
  const ctx = makeCtx();
  const out = await myUsage(ctx, { userId: 'nobody', days: 7 });
  assert.deepEqual(out.accounts, []);
});
