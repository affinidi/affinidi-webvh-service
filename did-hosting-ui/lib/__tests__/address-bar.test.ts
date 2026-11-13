/**
 * An enrolment link's invite token is read from the fragment (where links now
 * carry it) or, for links issued before, the query; then removed from the
 * address bar and the current history entry.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  readAddressParam,
  readPageParam,
  setNoReferrer,
  stripPageParam,
  withoutAddressParam,
} from "../address-bar";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("readAddressParam", () => {
  it("reads the token from the fragment", () => {
    expect(readAddressParam("https://h.example/enroll#token=frag", "token")).toBe("frag");
  });

  it("falls back to the query for links issued before", () => {
    expect(readAddressParam("https://h.example/enroll?token=query", "token")).toBe("query");
  });

  it("prefers the fragment when both are present", () => {
    expect(readAddressParam("https://h.example/enroll?token=q#token=f", "token")).toBe("f");
  });

  it("is null when absent or empty", () => {
    expect(readAddressParam("https://h.example/enroll", "token")).toBeNull();
    expect(readAddressParam("https://h.example/enroll#token=", "token")).toBeNull();
  });
});

describe("withoutAddressParam", () => {
  it("removes the token from the fragment", () => {
    expect(withoutAddressParam("https://h.example/enroll#token=s", "token")).toBe("/enroll");
  });

  it("removes it from the query and keeps the rest", () => {
    expect(withoutAddressParam("https://h.example/enroll?token=s&x=1#top", "token")).toBe(
      "/enroll?x=1#top",
    );
  });

  it("removes it from both at once", () => {
    expect(withoutAddressParam("https://h.example/enroll?token=q&x=1#token=f&y=2", "token")).toBe(
      "/enroll?x=1#y=2",
    );
  });

  it("is null when there is nothing to remove", () => {
    expect(withoutAddressParam("https://h.example/enroll?x=1", "token")).toBeNull();
  });
});

describe("page helpers", () => {
  function stubWindow(href: string) {
    const replaceState = vi.fn();
    vi.stubGlobal("window", {
      location: { href },
      history: { state: { key: "k" }, replaceState },
    });
    return replaceState;
  }

  it("reads and then strips the token from the current page", () => {
    const replaceState = stubWindow("https://h.example/enroll#token=secret");
    expect(readPageParam("token")).toBe("secret");
    stripPageParam("token");
    expect(replaceState).toHaveBeenCalledWith({ key: "k" }, "", "/enroll");
  });

  it("does not touch history when the token is absent", () => {
    const replaceState = stubWindow("https://h.example/enroll?x=1");
    stripPageParam("token");
    expect(replaceState).not.toHaveBeenCalled();
  });

  it("does nothing without a window or document", () => {
    expect(readPageParam("token")).toBeNull();
    expect(() => stripPageParam("token")).not.toThrow();
    expect(() => setNoReferrer()).not.toThrow();
  });

  it("adds the no-referrer meta once", () => {
    const added: { name: string; content: string }[] = [];
    vi.stubGlobal("document", {
      head: {
        querySelector: () => (added.length ? added[0] : null),
        prepend: (m: { name: string; content: string }) => added.push(m),
      },
      createElement: () => ({ name: "", content: "" }),
    });
    setNoReferrer();
    setNoReferrer();
    expect(added).toEqual([{ name: "referrer", content: "no-referrer" }]);
  });
});
