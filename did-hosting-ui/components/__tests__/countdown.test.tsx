// @vitest-environment jsdom
/**
 * The settings page's "honoured for" countdown ticks by itself, so only it
 * re-renders each second.
 */

import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Countdown, remainingLabel } from "../Countdown";

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date(1_000_000 * 1000));
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("remainingLabel", () => {
  it("is compact, two units, and says expiring once due", () => {
    expect(remainingLabel(1_000 + 45, 1_000)).toBe("45s");
    expect(remainingLabel(1_000 + 3_900, 1_000)).toBe("1h 5m");
    expect(remainingLabel(1_000, 1_000)).toBe("expiring");
  });
});

describe("Countdown", () => {
  it("counts down each second", () => {
    render(<Countdown expiresAt={1_000_000 + 3} />);
    expect(screen.getByText("3s")).toBeTruthy();
    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(screen.getByText("2s")).toBeTruthy();
    act(() => {
      vi.advanceTimersByTime(5_000);
    });
    expect(screen.getByText("expiring")).toBeTruthy();
  });
});
