import { describe, expect, it } from "vitest";
import { formatPerSecond, formatRate, pointSeconds, STEP_SECS } from "../usage-rate";

describe("pointSeconds", () => {
  it("is the full step for a closed point", () => {
    expect(pointSeconds(1_000, "24h", 1_000 + 5_000)).toBe(STEP_SECS["24h"]);
    expect(pointSeconds(0, "30d", 1e9)).toBe(14400);
  });
  it("is the elapsed time for the newest, filling point", () => {
    expect(pointSeconds(1_000, "24h", 1_120)).toBe(120);
  });
  it("is never below one second", () => {
    expect(pointSeconds(1_000, "1h", 1_000)).toBe(1);
    expect(pointSeconds(1_000, "1h", 900)).toBe(1);
  });
});

describe("formatPerSecond", () => {
  it("shows at most one decimal below 10/s, whole numbers above", () => {
    expect(formatPerSecond(0)).toBe("0/s");
    expect(formatPerSecond(0.03)).toBe("<0.1/s");
    expect(formatPerSecond(0.14)).toBe("0.1/s");
    expect(formatPerSecond(2.65)).toBe("2.7/s");
    expect(formatPerSecond(13.27)).toBe("13/s");
  });
  it("moves to whole numbers when one decimal would round to 10", () => {
    expect(formatPerSecond(9.96)).toBe("10/s");
  });
});

describe("formatRate", () => {
  it("divides the count by the seconds it covers", () => {
    expect(formatRate(796, 300)).toBe("2.7/s");
    expect(formatRate(1, 14400)).toBe("<0.1/s");
    expect(formatRate(0, 900)).toBe("0/s");
    expect(formatRate(90_000, 300)).toBe("300/s");
  });
});
