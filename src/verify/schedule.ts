// Latch — verify poll backoff schedule.
//
// Pure schedule, no timers. Given how long we have been polling (elapsed ms
// since the first attempt), return how long to wait before the next attempt, or
// null to give up (→ overall "failed").
//
// Shape: tight at first because most writes land in seconds, then
// exponential backoff so a slow/queued propagation costs almost nothing, capped
// so we eventually give up rather than poll forever.
//
//   elapsed < 2 min      → 10s intervals   (fast confirm for the common case)
//   then                 → 1m, 2m, 4m, 8m  (exponential backoff)
//   thereafter           → hold at 8m up to a 72h cap
//   elapsed >= 72h       → null (give up)
//
// The delays are driven with an INJECTED clock in pollUntil, so a poll's elapsed
// lands exactly on these breakpoints and the schedule is fully deterministic.

/** 10-second base interval for the first two minutes. */
export const FAST_INTERVAL_MS = 10_000;
/** Duration of the fast (10s) phase. */
export const FAST_PHASE_MS = 2 * 60_000; // 120s
/** Hard give-up cap. Past this, nextDelayMs returns null. */
export const MAX_ELAPSED_MS = 72 * 60 * 60 * 1000; // 259_200_000

/** Backoff breakpoints, keyed by the elapsed-ms window they apply to. */
const BACKOFF: ReadonlyArray<{ until: number; delay: number }> = [
  { until: 3 * 60_000, delay: 1 * 60_000 }, // [2m, 3m)  → 1m
  { until: 5 * 60_000, delay: 2 * 60_000 }, // [3m, 5m)  → 2m
  { until: 9 * 60_000, delay: 4 * 60_000 }, // [5m, 9m)  → 4m
];
/** Steady-state interval held from 9m to the cap. */
const STEADY_DELAY_MS = 8 * 60_000; // 8m

/**
 * Delay (ms) to wait before the next poll given `elapsedMs` since polling began,
 * or null once the 72h cap is reached (caller should stop and mark failed).
 */
export function nextDelayMs(elapsedMs: number): number | null {
  if (elapsedMs >= MAX_ELAPSED_MS) return null;
  if (elapsedMs < FAST_PHASE_MS) return FAST_INTERVAL_MS;
  for (const step of BACKOFF) {
    if (elapsedMs < step.until) return step.delay;
  }
  return STEADY_DELAY_MS;
}
