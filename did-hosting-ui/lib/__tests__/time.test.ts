import { describe, expect, it } from "vitest";

import { errorMessage } from "../errors";
import { plural, pluralForm } from "../plural";
import { formatDate, formatDuration, formatRelative } from "../time";

describe("plural", () => {
  it("picks the form the locale's plural rules choose", () => {
    expect(plural(0, "DID", "DIDs", "en")).toBe("0 DIDs");
    expect(plural(1, "DID", "DIDs", "en")).toBe("1 DID");
    expect(plural(1200, "DID", "DIDs", "en")).toBe("1,200 DIDs");
    expect(pluralForm(2, { one: "day", other: "days" }, "en")).toBe("days");
  });
});

describe("formatDuration", () => {
  it("long: one unit by default, more on request, zeros dropped", () => {
    expect(formatDuration(90_061)).toBe("1 day");
    expect(formatDuration(90_061, { maxParts: 2 })).toBe("1 day, 1 hour");
    expect(formatDuration(2 * 86_400, { maxParts: 2 })).toBe("2 days");
    expect(formatDuration(30)).toBe("0 minutes");
  });

  it("compact", () => {
    expect(formatDuration(45, { style: "compact" })).toBe("45s");
    expect(formatDuration(330, { style: "compact" })).toBe("5m");
    expect(formatDuration(3_900, { style: "compact", maxParts: 2 })).toBe("1h 5m");
    expect(formatDuration(0, { style: "compact" })).toBe("0s");
  });
});

describe("formatRelative", () => {
  const now = 1_000_000;
  it("past", () => {
    expect(formatRelative(now - 2, now)).toBe("just now");
    expect(formatRelative(now - 42, now)).toBe("42s ago");
    expect(formatRelative(now - 300, now)).toBe("5m ago");
    expect(formatRelative(now - 3 * 86_400, now)).toBe("3d ago");
  });
  it("future", () => {
    expect(formatRelative(now + 30, now)).toBe("any moment now");
    expect(formatRelative(now + 2 * 86_400 + 3 * 3_600, now)).toBe("in 2 days, 3 hours");
  });
  it("missing", () => {
    expect(formatRelative(null, now)).toBe("never");
  });
});

describe("formatDate", () => {
  it("renders a fallback for a missing value and a date otherwise", () => {
    expect(formatDate(null)).toBe("Never");
    expect(formatDate(undefined, { fallback: "—" })).toBe("—");
    expect(formatDate(1_700_000_000)).toMatch(/2023/);
    expect(formatDate("2026-01-02T03:04:05Z")).toMatch(/2026/);
    expect(formatDate("not a date")).toBe("Never");
  });
});

describe("errorMessage", () => {
  it("reads an Error, a string, or falls back", () => {
    expect(errorMessage(new Error("boom"))).toBe("boom");
    expect(errorMessage("plain")).toBe("plain");
    expect(errorMessage({ nope: 1 }, "fallback")).toBe("fallback");
    expect(errorMessage(new Error(""), "fallback")).toBe("fallback");
  });
});
