'use strict';
// Server-authoritative clock. All backend timestamps come from here so that
// (a) tests are deterministic and (b) the server clock — never the client's —
// is the single source of truth (UTC). Production uses the real clock;
// tests inject makeClock(startMs) and call advance().

// Deterministic, advanceable clock for tests.
function makeClock(startMs = 0) {
  let ms = startMs;
  return {
    nowMs: () => ms,
    now: () => new Date(ms),
    advance: (deltaMs) => { ms += deltaMs; return ms; },
    set: (absMs) => { ms = absMs; return ms; },
  };
}

// Real wall-clock (UTC epoch is timezone-agnostic).
const realClock = {
  nowMs: () => Date.now(),
  now: () => new Date(),
  advance: () => { throw new Error('realClock cannot be advanced'); },
  set: () => { throw new Error('realClock cannot be set'); },
};

module.exports = { makeClock, realClock };
