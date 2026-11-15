// @vitest-environment jsdom
/**
 * The DID detail page's actions and states: suspend / resume, delete behind
 * a typed name, the read-only parameters, the document editor offered only
 * with a wallet relay, and a failed read shown with Retry. Plus the nav
 * hiding admin-only pages from an owner.
 */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("expo-router", () => ({
  Link: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
  usePathname: () => "/",
}));
const setStringAsync = vi.fn(async (_: string) => true);
vi.mock("expo-clipboard", () => ({ setStringAsync: (v: string) => setStringAsync(v) }));

const setDidState = vi.fn();
const deleteDid = vi.fn();
const rollbackDid = vi.fn();
const api = { setDidState, deleteDid, rollbackDid };
vi.mock("../ApiProvider", () => ({ useApi: () => api }));

let role: "admin" | "owner" = "owner";
vi.mock("../AuthProvider", () => ({
  useAuth: () => ({ isAuthenticated: true, role, logout: vi.fn() }),
}));
vi.mock("../DomainSwitcher", () => ({ DomainSwitcher: () => null }));

import { resetFeedbackForTests } from "../../lib/feedback";
import { FeedbackHost } from "../FeedbackHost";
import { NavBar } from "../NavBar";
import { QueryView } from "../QueryState";
import { DangerZone } from "../did/DangerZone";
import { DidDocumentCard } from "../did/DidDocumentCard";
import { ParametersCard } from "../did/ParametersCard";

afterEach(() => {
  act(() => resetFeedbackForTests());
  cleanup();
  vi.clearAllMocks();
});

function zone(suspended: boolean, onDeleted = vi.fn(), onStateChanged = vi.fn()) {
  render(
    <>
      <DangerZone
        mnemonic="alice"
        versionCount={3}
        logEntryCount={3}
        suspended={suspended}
        onRolledBack={vi.fn()}
        onStateChanged={onStateChanged}
        onDeleted={onDeleted}
      />
      <FeedbackHost />
    </>,
  );
  return { onDeleted, onStateChanged };
}

describe("DangerZone", () => {
  it("suspends after confirming, and resumes without asking", async () => {
    setDidState.mockResolvedValue({});
    const { onStateChanged } = zone(false);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Suspend DID" }));
    });
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: "Suspend DID" }).at(-1)!);
    });
    expect(setDidState).toHaveBeenCalledWith("alice", "suspended");
    expect(onStateChanged).toHaveBeenCalled();
    expect(screen.getByRole("status").textContent).toMatch(/DID suspended/);

    cleanup();
    zone(true);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Resume DID" }));
    });
    expect(setDidState).toHaveBeenLastCalledWith("alice", "active");
  });

  it("deletes only once the DID's path has been typed", async () => {
    deleteDid.mockResolvedValue(undefined);
    const { onDeleted } = zone(false);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Delete DID" }));
    });
    const confirmButton = screen.getAllByRole("button", { name: "Delete DID" }).at(-1)!;
    expect(confirmButton.getAttribute("aria-disabled")).toBe("true");
    fireEvent.change(screen.getByLabelText("Type alice to confirm"), {
      target: { value: "alice" },
    });
    await act(async () => {
      fireEvent.click(confirmButton);
    });
    expect(deleteDid).toHaveBeenCalledWith("alice");
    expect(onDeleted).toHaveBeenCalled();
  });

  it("reports a failed delete in place, not in a browser alert", async () => {
    deleteDid.mockRejectedValue(new Error("refused"));
    const alert = vi.spyOn(window, "alert").mockImplementation(() => {});
    zone(false);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Delete DID" }));
    });
    fireEvent.change(screen.getByLabelText("Type alice to confirm"), {
      target: { value: "alice" },
    });
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: "Delete DID" }).at(-1)!);
    });
    expect(screen.getByRole("alert").textContent).toMatch(/Could not delete the DID.*refused/);
    expect(alert).not.toHaveBeenCalled();
  });
});

describe("DidDocumentCard", () => {
  const entries = [{ versionId: "1-x", versionTime: null, state: { id: "did:x" }, parameters: {} }];
  const card = (canPublish: boolean) => (
    <DidDocumentCard
      logEntries={entries as never}
      selectedVersion={0}
      onSelectVersion={vi.fn()}
      editing={false}
      onEditingChange={vi.fn()}
      canPublish={canPublish}
      publishing={false}
      onPublish={vi.fn()}
      delegationWarning={null}
      consentPanel={null}
    />
  );

  it("offers Edit only when an agent can sign the change, and says why otherwise", () => {
    render(card(false));
    expect(screen.queryByRole("button", { name: "Edit the document" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Copy to Upload/ })).toBeNull();
    expect(screen.getByText(/must be signed by the DID's agent/)).toBeTruthy();
    cleanup();
    render(card(true));
    expect(screen.getByRole("button", { name: "Edit the document" })).toBeTruthy();
  });
});

describe("ParametersCard", () => {
  it("is read-only and copies the parameters as JSON", async () => {
    const latest = {
      versionId: "2-y",
      versionTime: null,
      state: { alsoKnownAs: ["https://example.com/@alice"] },
      parameters: { portable: true, ttl: 300, watchers: ["https://w.example"] },
    };
    render(<ParametersCard latest={latest as never} knownWatcherUrls={[]} />);
    expect(screen.queryByRole("button", { name: /Edit Parameters/ })).toBeNull();
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: "Copy the latest entry's parameters as JSON" }),
      );
    });
    expect(JSON.parse(setStringAsync.mock.calls[0]![0])).toEqual(latest.parameters);
  });
});

describe("QueryView", () => {
  it("shows an error with Retry instead of empty data, then the data", async () => {
    const refetch = vi.fn(async () => {});
    const { rerender } = render(
      <QueryView
        query={{ data: undefined, error: new Error("boom"), loading: false, refetch }}
        what="the widgets"
      >
        {(d: string[]) => <span>{d.length} widgets</span>}
      </QueryView>,
    );
    expect(screen.getByRole("alert").textContent).toMatch(/Could not load the widgets\.boom/);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Retry loading the widgets" }));
    });
    expect(refetch).toHaveBeenCalled();
    rerender(
      <QueryView query={{ data: ["a"], error: null, loading: false, refetch }} what="the widgets">
        {(d: string[]) => <span>{d.length} widgets</span>}
      </QueryView>,
    );
    expect(screen.getByText("1 widgets")).toBeTruthy();
  });
});

describe("NavBar", () => {
  it("hides the admin-only pages, Access included, from an owner", () => {
    role = "owner";
    render(<NavBar />);
    expect(screen.queryByRole("link", { name: "Access" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Domains" })).toBeNull();
    expect(screen.getAllByRole("link", { name: "DIDs" }).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Sign out" })).toBeTruthy();
    cleanup();
    role = "admin";
    render(<NavBar />);
    expect(screen.getAllByRole("link", { name: "Access" }).length).toBeGreaterThan(0);
  });
});
