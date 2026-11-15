// @vitest-environment jsdom
/**
 * Smoke tests for the DID list: signed out, loading, empty, and a list with
 * rows — and that a row's actions are not nested inside its link.
 */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { DidListPage, DidListQuery, DidRecord } from "../../lib/api";
import { clearQueryCache } from "../../lib/query";

vi.mock("expo-router", () => ({
  Link: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useLocalSearchParams: () => ({}),
}));
vi.mock("expo-clipboard", () => ({ setStringAsync: vi.fn(async () => true) }));

let currentDomain: string | null = null;
let auth = { isAuthenticated: true, restored: true, role: "owner", did: "did:example:me" };
vi.mock("../AuthProvider", () => ({ useAuth: () => auth }));
vi.mock("../DomainProvider", () => ({
  useDomains: () => ({
    domains: [],
    currentDomain,
    defaultDomain: null,
    loaded: true,
  }),
}));

const listDidPage = vi.fn<(q?: DidListQuery) => Promise<DidListPage>>();
vi.mock("../ApiProvider", () => ({
  useApi: () => ({ listDidPage, checkName: vi.fn(), createDid: vi.fn() }),
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
  currentDomain = null;
  auth = { isAuthenticated: true, restored: true, role: "owner", did: "did:example:me" };
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("DID list", () => {
  it("reads nothing for a signed-out visitor (the route guard sends them to sign in)", () => {
    auth = { ...auth, isAuthenticated: false };
    render(<DidList />);
    expect(screen.getByLabelText("Loading — manage DIDs")).toBeTruthy();
    expect(screen.queryByText(/Please log in/)).toBeNull();
    expect(listDidPage).not.toHaveBeenCalled();
  });

  it("shows a failed load as an error with Retry, not as an empty list", async () => {
    listDidPage.mockRejectedValueOnce(new Error("control plane down"));
    await act(async () => {
      render(<DidList />);
    });
    expect(screen.getByRole("alert").textContent).toMatch(/Could not load the DIDs/);
    expect(screen.queryByText(/No DIDs yet/)).toBeNull();
    listDidPage.mockResolvedValue({ records: [did("alice")] });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Retry loading the DIDs" }));
    });
    expect(screen.getByRole("link", { name: "alice" })).toBeTruthy();
  });

  it("shows a spinner while the list loads", () => {
    listDidPage.mockReturnValue(new Promise(() => {}));
    render(<DidList />);
    expect(screen.getByLabelText("Loading DIDs")).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "Your DIDs" })).toBeTruthy();
  });

  it("says so when there are no DIDs", async () => {
    listDidPage.mockResolvedValue({ records: [] });
    await act(async () => {
      render(<DidList />);
    });
    expect(screen.getByText("No DIDs yet. Create one to get started.")).toBeTruthy();
  });

  it("lists DIDs with a pluralised count, a link per name and actions beside it", async () => {
    listDidPage.mockResolvedValue({ records: [did("alice"), did("bob")] });
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
    listDidPage.mockResolvedValue({ records: [did("solo")] });
    await act(async () => {
      render(<DidList />);
    });
    expect(screen.getByText("1 DID")).toBeTruthy();
  });

  it("asks the server for one page of the pinned domain, and the next only on demand", async () => {
    currentDomain = "example.com";
    listDidPage.mockImplementation(async (q) =>
      q?.cursor === "c1"
        ? { records: [did("carol")] }
        : { records: [did("alice"), did("bob")], nextCursor: "c1" },
    );
    await act(async () => {
      render(<DidList />);
    });
    expect(listDidPage).toHaveBeenCalledTimes(1);
    expect(listDidPage.mock.calls[0]![0]).toEqual({ domain: "example.com", limit: 50 });
    expect(screen.getByText(/2 DIDs shown · more available/)).toBeTruthy();

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    });
    expect(listDidPage).toHaveBeenCalledTimes(2);
    expect(listDidPage.mock.calls[1]![0]).toEqual({
      domain: "example.com",
      limit: 50,
      cursor: "c1",
    });
    expect(screen.getByText("3 DIDs")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  });

  it("sends the search to the server once typing pauses, starting paging over", async () => {
    vi.useFakeTimers();
    try {
      listDidPage.mockImplementation(async (q) =>
        q?.search ? { records: [did("alice")] } : { records: [did("alice"), did("bob")] },
      );
      await act(async () => {
        render(<DidList />);
      });
      const box = screen.getByRole("textbox", { name: "Search DIDs" });
      await act(async () => {
        fireEvent.change(box, { target: { value: " ali" } });
      });
      // Not yet: the search waits for typing to pause.
      expect(listDidPage).toHaveBeenCalledTimes(1);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(400);
      });
      expect(listDidPage).toHaveBeenCalledTimes(2);
      expect(listDidPage.mock.calls[1]![0]).toEqual({ search: "ali", limit: 50 });
      expect(screen.getByText("1 DID")).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });
});
