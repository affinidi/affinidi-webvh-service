/**
 * Per-second rates for the usage chart.
 *
 * `stats/timeseries` answers one point per display step, summing the 5-minute
 * buckets the step covers (`did-hosting-control` `query_timeseries`): 5 min
 * for 1h, 15 min for 24h, 1 h for 7d, 4 h for 30d. The newest point is still
 * filling, so its rate is over the time it has actually covered.
 */

import type { TimeRange } from "./api";

/** The width of one point, in seconds, for each range. */
export const STEP_SECS: Record<TimeRange, number> = {
  "1h": 300,
  "24h": 900,
  "7d": 3600,
  "30d": 14400,
};

/** Seconds a point starting at `start` covers: a full step, or up to `now`
 *  for the newest one. Never less than one second. */
export function pointSeconds(start: number, range: TimeRange, now: number): number {
  const step = STEP_SECS[range];
  return Math.max(1, Math.min(step, now - start));
}

/** `count` over `seconds`, as a short per-second rate. Below 10/s one
 *  decimal (`2.7/s`), with a non-zero rate that would show as 0.0 written
 *  `<0.1/s`; from 10/s whole numbers (`13/s`); nothing at all is `0/s`. */
export function formatRate(count: number, seconds: number): string {
  if (count <= 0 || seconds <= 0) return "0/s";
  return formatPerSecond(count / seconds);
}

/** {@link formatRate} for a rate already per second. Halves round up on the
 *  shown digit (2.65 → 2.7), which binary floating point would otherwise
 *  round down. */
export function formatPerSecond(rate: number): string {
  if (!(rate > 0)) return "0/s";
  const tenths = Math.round(rate * 10 + 1e-9) / 10;
  if (tenths >= 10) return `${Math.round(rate + 1e-9).toLocaleString()}/s`;
  if (tenths === 0) return "<0.1/s";
  return `${tenths.toFixed(1)}/s`;
}
