'use strict';
// Anchor-aligned retention prune (Addendum B: 7 days) for the append-only
// ledgers. Closes review gap #1.
//
// The prune boundary is chosen by TIME but the delete is BY SEQ, so we never
// reintroduce the raw-time-TTL bug (a serverTs delete would cut mid-anchor and
// leave the retained tail's prevHash un-anchored → verify fails).
//
//   boundary = the largest anchor A such that event(A.seqHigh).serverTs is older
//              than the retention window AND A.seqHigh < head.seq
//   delete   = events with seq <= boundary  (retain seq > boundary; the tail then
//              starts exactly at boundary+1, which verifyEvents checks against the
//              anchor at seqHigh === firstSeq-1)
//
// INVARIANTS:
//   - Never prunes to empty (boundary is always strictly below the head).
//   - Never deletes an anchor row (anchors are the checkpoints; kept forever).
//   - Runs under a SEPARATE privileged connection in production (the app's own
//     Mongo role stays insert+find-only for tamper-evidence — see mongoRepo.js).
//
// ROLE SPLIT (Phase 6 Task 3): `events`/`anchors` are the READ handles (always
// the app-role ctx.repo — getHead/findOne/find are insert+find-only ops).
// `deleteEvents` is the DELETE handle: when the caller has a separate
// delete-capable connection (ctx.pruneRepo, see mongoRepo.js/context.js) it
// passes that collection's handle here so the actual deleteMany runs under
// the privileged role. When omitted, it defaults to `events` — the exact same
// handle used for reads — reproducing today's single-connection behavior
// byte-for-byte (back-compat for callers with no pruneRepo).

const DAY_MS = 24 * 60 * 60 * 1000;

async function pruneAnchorAligned(ctx, { events, anchors, retentionDays, deleteEvents }) {
  const del = deleteEvents || events; // PRUNE ROLE handle for the delete below (app-role `events` if not split)
  const head = await events.getHead();
  if (!head) return { pruned: 0, boundarySeq: 0 };
  const cutoffMs = ctx.clock.nowMs() - (retentionDays != null ? retentionDays : ctx.config.retentionDays) * DAY_MS;
  const anchorList = (await anchors.find({})).sort((a, b) => a.seqHigh - b.seqHigh);

  let boundarySeq = 0;
  for (const a of anchorList) {
    if (a.seqHigh >= head.seq) break; // never prune the head or above (never empty)
    const ev = await events.findOne({ seq: a.seqHigh });
    if (!ev) { boundarySeq = a.seqHigh; continue; } // already pruned below — keep advancing
    if (new Date(ev.serverTs).getTime() < cutoffMs) {
      boundarySeq = a.seqHigh; // this anchor's covered prefix is past retention
    } else {
      break; // anchors are time-ordered; the rest are within retention
    }
  }
  if (boundarySeq <= 0) return { pruned: 0, boundarySeq: 0 };
  // The ONLY delete on an append-only ledger — routed through the prune role
  // (`del`) rather than the read handle (`events`) whenever the two differ.
  const pruned = await del.deleteBelowSeq(boundarySeq); // delete strictly by seq
  return { pruned, boundarySeq };
}

module.exports = { pruneAnchorAligned };
