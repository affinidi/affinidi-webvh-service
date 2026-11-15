// @vitest-environment jsdom
/**
 * Smoke tests for the DID list: signed out, loading, empty, and a list with
 * rows — and that a row's actions are not nested inside its link.
 */

import { act, cleanup, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { DidRecord } from "../../lib/api";
import { clearQueryCache } from "../../lib/query";

vi.mock("expo-router", () => ({
  Link: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useLocalSearchParams: () => ({}),
}));
vi.mock("expo-clipboard", () => ({ setStringAsync: vi.fn(async () => true) }));

let auth = { isAuthenticated: true, restored: true, role: "owner", did: "did:example:me" };
vi.mock("../AuthProvider", () => ({ useAuth: () => auth }));
vi.mock("../DomainProvider", () => ({
  useDomains: () => ({
    domains: [],
    currentDomain: null,
    defaultDomain: null,
    loaded: true,
  }),
}));

const listDids = vi.fn<(owner?: string) => Promise<DidRecord[]>>();
vi.mock("../ApiProvider", () => ({
  useApi: () => ({ listDids, checkName: vi.fn(), createDid: vi.fn() }),
}));

// Fork-independent: the chips have their own tests.
vi.mock("../AgentNameChips", () => ({
  AgentNameChips: () => null,
  servedNames: () => [],
}));

import DidList from "../../app/dids/index";

function did(mnemonic: string, over: Partial<DidRecord> = {}): DidRecord {
  return {
    mnemonic,
    owner: "did:example:me",
    createdAt: 1_700_000_000,
    updatedAt: 1_700_000_000,
    versionCount: 1,
    didId: `did:webvh:QmScid:example.com:${mnemonic}`,
    didUrl: null,
    totalResolves: 3,
    disabled: false,
    ...over,
  };
}

beforeEach(() => {
  clearQueryCache();
  auth = { isAuthenticated: true, restored: true, role: "owner", did: "did:example:me" };
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("DID list", () => {
  it("asks a signed-out visitor to log in", () => {
    auth = { ...auth, isAuthenticated: false };
    render(<DidList />);
    expect(screen.getByText("Please log in to manage DIDs.")).toBeTruthy();
    expect(listDids).not.toHaveBeenCalled();
  });

  it("shows a spinner while the list loads", () => {
    listDids.mockReturnValue(new Promise(() => {}));
    render(<DidList />);
    expect(screen.getByLabelText("Loading DIDs")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "Your DIDs" })).toBeTruthy();
  });

  it("says so when there are no DIDs", async () => {
    listDids.mockResolvedValue([]);
    await act(async () => {
      render(<DidList />);
    });
    expect(screen.getByText("No DIDs yet. Create one to get started.")).toBeTruthy();
  });

  it("lists DIDs with a pluralised count, a link per name and actions beside it", async () => {
    listDids.mockResolvedValue([did("alice"), did("bob")]);
    await act(async () => {
      render(<DidList />);
    });
    expect(screen.getByText("2 DIDs")).toBeTruthy();
    const link = screen.getByRole("link", { name: "alice" });
    expect(link.getAttribute("href")).toBe("/dids/alice");
    // The copy and QR buttons are siblings of the link, never inside it.
    const copy = screen.getByRole("button", { name: "Copy DID of alice" });
    expect(link.contains(copy)).toBe(false);
    expect(copy.closest("a")).toBeNull();
    expect(screen.getByRole("button", { name: "Show a QR code for alice" })).toBeTruthy();
    // Sort state is announced on the column header.
    const header = screen
      .getByRole("button", { name: "Sort by Name" })
      .closest("[role=columnheader]")!;
    expect(header.getAttribute("aria-sort")).toBe("ascending");
  });

  it("uses the singular for one DID", async () => {
    listDids.mockResolvedValue([did("solo")]);
    await act(async () => {
      render(<DidList />);
    });
    expect(screen.getByText("1 DID")).toBeTruthy();
  });
});
