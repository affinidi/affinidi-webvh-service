/**
 * An enrolment link's invite token is read once and then removed from the
 * address bar and the current history entry.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { stripQueryParam } from "../address-bar";

function stubWindow(href: string) {
  const replaceState = vi.fn();
  vi.stubGlobal("window", {
    location: { href },
    history: { state: { key: "k" }, replaceState },
  });
  return replaceState;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("stripQueryParam", () => {
  it("removes the parameter and keeps the rest of the address", () => {
    const replaceState = stubWindow("https://host.example/enroll?token=secret&x=1#top");
    stripQueryParam("token");
    expect(replaceState).toHaveBeenCalledWith({ key: "k" }, "", "/enroll?x=1#top");
  });

  it("leaves the address alone when the parameter is absent", () => {
    const replaceState = stubWindow("https://host.example/enroll?x=1");
    stripQueryParam("token");
    expect(replaceState).not.toHaveBeenCalled();
  });

  it("does nothing without a window", () => {
    expect(() => stripQueryParam("token")).not.toThrow();
  });
});
