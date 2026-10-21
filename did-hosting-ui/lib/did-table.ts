/**
 * The DID list's search and sort, kept apart from the page so they are tested.
 */

import type { DidRecord } from "./api";
import { parseScid } from "./did-scid";

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

/** A `did:webvh` for a table cell: the method, the SCID's first 12
 *  characters, and the last segment (the slot's name, or the host for a
 *  root DID). The domain between them is the same on every row of a
 *  filtered list, so it is dropped; the full DID is on hover, Copy and QR.
 *  Other methods fall back to [`truncateDid`]. */
export function compactDid(did: string): string {
  // did:scid: the SCID's first 12 characters, then the last segment of the
  // `src` locator where there is one. A bare did:scid is the SCID alone.
  const scidParts = parseScid(did);
  if (scidParts) {
    const { scid: id, src } = scidParts;
    const head = id.length > 12 ? `${id.slice(0, 12)}…` : id;
    const last = src?.replace(/\/+$/, "").split("/").pop();
    return last ? `did:scid:vh:1:${head}?src=…${last}` : `did:scid:vh:1:${head}`;
  }
  const parts = did.split(":");
  if (parts[0] !== "did" || parts[1] !== "webvh" || parts.length < 4) {
    return truncateDid(did);
  }
  const scid = parts[2];
  const head = scid.length > 12 ? `${scid.slice(0, 12)}…` : scid;
  return `did:webvh:${head}:${parts[parts.length - 1]}`;
}

/** Shorten a long DID for a table cell, keeping both ends: the method and
 *  SCID prefix, and the host/path that tell slots apart. */
export function truncateDid(did: string, max = 48): string {
  if (did.length <= max) return did;
  const keep = max - 1;
  const head = Math.ceil(keep * 0.45);
  return `${did.slice(0, head)}…${did.slice(did.length - (keep - head))}`;
}

/** Monospace advance per em, a little generous: most faces are 0.6. */
const MONO_EM = 0.62;
/** Proportional text (badges), per character at its font size. */
const SANS_EM = 0.6;

/** What a name cell shows on one line each, so its width can be sized. */
export interface NameCellContent {
  /** The slot name, in the 14px monospace of the table. */
  name: string;
  /** Badges beside the name (`did:webvh`, `You`, `Suspended`). */
  badges?: string[];
  /** Agent names under it, each a `@name` chip with a Copy button. */
  chips?: string[];
}

/** The name column's width: wide enough for the longest name with its
 *  badges, or its widest agent-name chip, and no wider. Estimated from
 *  character counts (the name and chips are monospace), so it doesn't
 *  depend on rendered rows — the list is virtualised. Clamped so a short
 *  list keeps its header readable and one long name can't take the table. */
export function nameColumnWidth(
  cells: NameCellContent[],
  { min = 140, max = 360 }: { min?: number; max?: number } = {},
): number {
  const CELL_PADDING = 16;
  const BADGE_CHROME = 16 + 4; // padding + gap
  const CHIP_CHROME = 16 + 8 + 44; // padding + gap + Copy button
  let widest = 0;
  for (const c of cells) {
    const line =
      c.name.length * 14 * MONO_EM +
      (c.badges ?? []).reduce((w, b) => w + b.length * 11 * SANS_EM + BADGE_CHROME, 0);
    const chip = Math.max(
      0,
      ...(c.chips ?? []).map((n) => (n.length + 1) * 12 * MONO_EM + CHIP_CHROME),
    );
    widest = Math.max(widest, line, chip);
  }
  return Math.round(Math.min(max, Math.max(min, widest + CELL_PADDING)));
}

/** The width of the longest compact DID (see [`compactDid`]) in the table's
 *  12px monospace, so Copy and QR sit just after it on every row. */
export function didTextWidth(
  dids: (string | null)[],
  { min = 160, max = 400 }: { min?: number; max?: number } = {},
): number {
  const longest = Math.max(0, ...dids.map((d) => (d ? compactDid(d).length : 0)));
  return Math.round(Math.min(max, Math.max(min, longest * 12 * MONO_EM)));
}
