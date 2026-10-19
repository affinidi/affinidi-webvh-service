import { describe, expect, it } from "vitest";
import type { DidRecord } from "../api";
import { matchesSearch, nextSort, sortDids, truncateDid } from "../did-table";

function rec(over: Partial<DidRecord>): DidRecord {
  return {
    mnemonic: "m",
    owner: "did:key:o",
    createdAt: 0,
    updatedAt: 0,
    versionCount: 1,
    didId: null,
    didUrl: null,
    totalResolves: 0,
    disabled: false,
    ...over,
  };
}

const a = rec({ mnemonic: "alpha", didId: "did:webvh:Qm1:example.com:alpha", method: "webvh", versionCount: 3, createdAt: 30, updatedAt: 10, totalResolves: 5 });
const b = rec({ mnemonic: "bravo", didId: "did:web:example.com:bravo", method: "web", versionCount: 1, createdAt: 10, updatedAt: 30, totalResolves: 500 });
const c = rec({ mnemonic: "charlie", versionCount: 0, createdAt: 20, updatedAt: 20, totalResolves: 50, agentNames: [{ name: "shop" } as never] });

describe("matchesSearch", () => {
  it("matches name, DID and method case-insensitively", () => {
    expect(matchesSearch(a, "ALPHA")).toBe(true);
    expect(matchesSearch(a, "qm1")).toBe(true);
    expect(matchesSearch(b, "did:web")).toBe(true);
    expect(matchesSearch(a, "did:web:")).toBe(false);
    expect(matchesSearch(c, "shop")).toBe(true);
  });
  it("needs every term", () => {
    expect(matchesSearch(a, "webvh alpha")).toBe(true);
    expect(matchesSearch(a, "webvh bravo")).toBe(false);
  });
  it("matches everything when empty", () => {
    expect(matchesSearch(c, "   ")).toBe(true);
  });
});

describe("sortDids", () => {
  const names = (l: DidRecord[]) => l.map((d) => d.mnemonic);
  it("sorts each column both ways", () => {
    expect(names(sortDids([c, a, b], { key: "mnemonic", dir: "asc" }))).toEqual(["alpha", "bravo", "charlie"]);
    expect(names(sortDids([a, b, c], { key: "resolves", dir: "desc" }))).toEqual(["bravo", "charlie", "alpha"]);
    expect(names(sortDids([a, b, c], { key: "created", dir: "asc" }))).toEqual(["bravo", "charlie", "alpha"]);
    expect(names(sortDids([a, b, c], { key: "updated", dir: "desc" }))).toEqual(["bravo", "charlie", "alpha"]);
    expect(names(sortDids([a, b, c], { key: "versions", dir: "asc" }))).toEqual(["charlie", "bravo", "alpha"]);
  });
  it("does not reorder its input", () => {
    const input = [b, a];
    sortDids(input, { key: "mnemonic", dir: "asc" });
    expect(names(input)).toEqual(["bravo", "alpha"]);
  });
});

describe("nextSort", () => {
  it("flips the same column, starts a new one at its default", () => {
    expect(nextSort({ key: "resolves", dir: "desc" }, "resolves")).toEqual({ key: "resolves", dir: "asc" });
    expect(nextSort({ key: "resolves", dir: "asc" }, "mnemonic")).toEqual({ key: "mnemonic", dir: "asc" });
    expect(nextSort({ key: "mnemonic", dir: "asc" }, "updated")).toEqual({ key: "updated", dir: "desc" });
  });
});

describe("truncateDid", () => {
  it("keeps short DIDs and both ends of long ones", () => {
    expect(truncateDid("did:web:x")).toBe("did:web:x");
    const long = "did:webvh:QmSNo2TJRq5xiiYhHZNrTqoaq8bivffWq4PZXjQQAzvNtr:webvh.storm.ws:angry-derive";
    const t = truncateDid(long, 40);
    expect(t.length).toBe(40);
    expect(t.startsWith("did:webvh:Qm")).toBe(true);
    expect(t.endsWith("angry-derive")).toBe(true);
  });
});
