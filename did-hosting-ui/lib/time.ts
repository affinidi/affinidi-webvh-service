/**
 * Dates, durations and relative times — one of each, so every screen says
 * "3 days" or "5m ago" the same way.
 *
 * Every input is epoch **seconds** (what the control plane sends) unless the
 * name says otherwise. Dates render in the viewer's locale.
 */

import { plural } from "./plural";

/** Now, in epoch seconds. */
export function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

export interface FormatDateOptions {
  /** Include the time of day. Default: the date alone. */
  withTime?: boolean;
  /** What to show for a missing timestamp. Default: `"Never"`. */
  fallback?: string;
}

/**
 * An absolute date — `"Nov 15, 2026"`, or `"Nov 15, 2026, 10:31 AM"` with
 * `withTime`. Accepts epoch seconds, or an ISO string / `Date` for the few
 * values the wire carries that way.
 */
export function formatDate(
  value: number | string | Date | null | undefined,
  opts: FormatDateOptions = {},
): string {
  const { withTime = false, fallback = "Never" } = opts;
  if (value === null || value === undefined || value === "" || value === 0) return fallback;
  const date =
    typeof value === "number"
      ? new Date(value * 1000)
      : value instanceof Date
        ? value
        : new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  });
}

const UNITS = [
  { secs: 86_400, short: "d", one: "day", other: "days" },
  { secs: 3_600, short: "h", one: "hour", other: "hours" },
  { secs: 60, short: "m", one: "minute", other: "minutes" },
  { secs: 1, short: "s", one: "second", other: "seconds" },
] as const;

export interface FormatDurationOptions {
  /** `"long"` — `"2 days, 3 hours"`; `"compact"` — `"2d 3h"`. Default long. */
  style?: "long" | "compact";
  /** How many units, largest first. Default 1. */
  maxParts?: number;
  /** The smallest unit shown, in seconds (60 hides seconds). Default 60 for
   *  long, 1 for compact. */
  minUnitSecs?: number;
}

/**
 * A length of time: `formatDuration(90061)` is `"1 day"`,
 * `formatDuration(90061, { maxParts: 2 })` is `"1 day, 1 hour"`,
 * `formatDuration(330, { style: "compact" })` is `"5m"`.
 *
 * Zero-valued units after the first are skipped (`"2 days"`, not
 * `"2 days, 0 hours"`).
 */
export function formatDuration(seconds: number, opts: FormatDurationOptions = {}): string {
  const { style = "long", maxParts = 1 } = opts;
  const minUnit = opts.minUnitSecs ?? (style === "long" ? 60 : 1);
  let left = Math.max(0, Math.floor(seconds));
  const parts: string[] = [];
  for (const unit of UNITS) {
    if (unit.secs < minUnit) break;
    if (parts.length >= maxParts) break;
    const n = Math.floor(left / unit.secs);
    if (n === 0) {
      // Once a unit is shown, a zero below it ends the reading — "1 day",
      // not "1 day, 0 hours".
      if (parts.length > 0) break;
      continue;
    }
    left -= n * unit.secs;
    parts.push(style === "compact" ? `${n}${unit.short}` : plural(n, unit.one, unit.other));
  }
  if (parts.length === 0) {
    const smallest = UNITS.find((u) => u.secs === minUnit) ?? UNITS[UNITS.length - 1]!;
    return style === "compact" ? `0${smallest.short}` : plural(0, smallest.one, smallest.other);
  }
  return parts.join(style === "compact" ? " " : ", ");
}

/**
 * A point in time relative to now.
 *
 * Past: `"just now"`, `"42s ago"`, `"5m ago"`, `"3h ago"`, `"2d ago"`.
 * Future: `"any moment now"` within a minute, else `"in 3 days, 2 hours"`.
 * `fallback` (default `"never"`) for a missing timestamp.
 */
export function formatRelative(
  epochSecs: number | null | undefined,
  now: number = nowSecs(),
  fallback = "never",
): string {
  if (!epochSecs) return fallback;
  const delta = epochSecs - now;
  if (delta > 0) {
    if (delta <= 60) return "any moment now";
    return `in ${formatDuration(delta, { maxParts: 2 })}`;
  }
  const ago = -delta;
  if (ago < 5) return "just now";
  return `${formatDuration(ago, { style: "compact" })} ago`;
}
