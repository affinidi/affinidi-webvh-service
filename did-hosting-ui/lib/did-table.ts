/**
 * The DID list's search and sort, kept apart from the page so they are tested.
 */

import type { DidRecord } from "./api";

export type DidSortKey =
  | "mnemonic"
  | "didId"
  | "versions"
  | "created"
  | "updated"
  | "resolves";

export type SortDir = "asc" | "desc";

export interface DidSort {
  key: DidSortKey;
  dir: SortDir;
}

/** Numbers and dates read best largest/newest first; text A→Z. */
export function defaultDir(key: DidSortKey): SortDir {
  return key === "mnemonic" || key === "didId" ? "asc" : "desc";
}

/** Clicking a header: the same column flips, a new one starts at its default. */
export function nextSort(current: DidSort, key: DidSortKey): DidSort {
  if (current.key === key) {
    return { key, dir: current.dir === "asc" ? "desc" : "asc" };
  }
  return { key, dir: defaultDir(key) };
}

/** Case-insensitive match on the name, DID, method (`webvh` or `did:webvh`),
 *  domain, and agent names. Every whitespace-separated term must match. */
export function matchesSearch(d: DidRecord, query: string): boolean {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const hay = [
    d.mnemonic,
    d.didId ?? "",
    d.method ? `did:${d.method}` : "",
    d.domain ?? "",
    ...(d.agentNames ?? []).map((n) => n.name),
  ]
    .join(" ")
    .toLowerCase();
  return terms.every((t) => hay.includes(t));
}

function value(d: DidRecord, key: DidSortKey): string | number {
  switch (key) {
    case "mnemonic":
      return d.mnemonic;
    case "didId":
      return d.didId ?? "";
    case "versions":
      return d.versionCount;
    case "created":
      return d.createdAt;
    case "updated":
      return d.updatedAt;
    case "resolves":
      return d.totalResolves;
  }
}

/** A sorted copy. Ties fall back to the name, so the order is stable. */
export function sortDids(dids: DidRecord[], sort: DidSort): DidRecord[] {
  const sign = sort.dir === "asc" ? 1 : -1;
  return [...dids].sort((a, b) => {
    const va = value(a, sort.key);
    const vb = value(b, sort.key);
    const c =
      typeof va === "number" && typeof vb === "number"
        ? va - vb
        : String(va).localeCompare(String(vb));
    return c !== 0 ? c * sign : a.mnemonic.localeCompare(b.mnemonic);
  });
}

/** Shorten a long DID for a table cell, keeping both ends: the method and
 *  SCID prefix, and the host/path that tell slots apart. */
export function truncateDid(did: string, max = 48): string {
  if (did.length <= max) return did;
  const keep = max - 1;
  const head = Math.ceil(keep * 0.45);
  return `${did.slice(0, head)}…${did.slice(did.length - (keep - head))}`;
}
