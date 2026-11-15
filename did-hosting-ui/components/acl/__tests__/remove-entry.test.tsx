// @vitest-environment jsdom
/**
 * Removing an ACL entry: one dialog with three choices, the owned DIDs listed,
 * typed confirmation before deleting them, per-DID progress, and a partial
 * failure that keeps the entry and says which DIDs failed.
 */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { DidRecord } from "../../../lib/api";
import { getFeedbackState, resetFeedbackForTests } from "../../../lib/feedback";

const listDids = vi.fn<(owner?: string) => Promise<DidRecord[]>>();
const deleteDid = vi.fn<(m: string) => Promise<void>>();
const deleteAcl = vi.fn<(did: string) => Promise<void>>();
// One object, as the real provider gives: the dialog reads on `api` changing.
const api = { listDids, deleteDid, deleteAcl };
vi.mock("../../ApiProvider", () => ({
  useApi: () => api,
}));

import { RemoveEntryDialog, deletePhrase } from "../RemoveEntryDialog";

const OWNER = "did:web:bob.example";

function rec(mnemonic: string): DidRecord {
  return {
    mnemonic,
    owner: OWNER,
    createdAt: 1,
    updatedAt: 1,
    versionCount: 1,
    didId: null,
    didUrl: null,
    totalResolves: 0,
    disabled: false,
    domain: "a.example",
  };
}

beforeEach(() => {
  deleteAcl.mockResolvedValue(undefined);
  deleteDid.mockResolvedValue(undefined);
});
afterEach(() => {
  act(() => resetFeedbackForTests());
  cleanup();
  vi.clearAllMocks();
});

async function renderDialog(onClose = vi.fn()) {
  await act(async () => {
    render(<RemoveEntryDialog did={OWNER} onClose={onClose} />);
  });
  return { onClose };
}

describe("RemoveEntryDialog", () => {
  it("offers a single removal for an account that owns no DIDs", async () => {
    listDids.mockResolvedValue([]);
    const { onClose } = await renderDialog();
    expect(screen.queryByRole("button", { name: /delete/i })).toBeNull();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Remove access only" }));
    });
    expect(deleteAcl).toHaveBeenCalledWith(OWNER);
    expect(deleteDid).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
    expect(getFeedbackState().toasts[0]?.title).toBe("Access removed");
  });

  it("lists the owned DIDs and keeps them on “Remove access only”", async () => {
    listDids.mockResolvedValue([rec("alice"), rec("carol")]);
    await renderDialog();
    expect(screen.getByText("a.example/alice")).toBeTruthy();
    expect(screen.getByText("a.example/carol")).toBeTruthy();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Remove access only" }));
    });
    expect(deleteDid).not.toHaveBeenCalled();
    expect(deleteAcl).toHaveBeenCalledWith(OWNER);
  });

  it("Cancel does nothing at all", async () => {
    listDids.mockResolvedValue([rec("alice")]);
    const { onClose } = await renderDialog();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    });
    expect(onClose).toHaveBeenCalled();
    expect(deleteDid).not.toHaveBeenCalled();
    expect(deleteAcl).not.toHaveBeenCalled();
  });

  it("deletes every DID, then the entry, once the phrase is typed", async () => {
    listDids.mockResolvedValue([rec("alice"), rec("carol")]);
    const { onClose } = await renderDialog();
    const both = screen.getByRole("button", { name: "Remove access and delete 2 DIDs" });
    expect(both.getAttribute("aria-disabled")).toBe("true");
    fireEvent.change(screen.getByLabelText(`To delete the DIDs too, type ${deletePhrase(2)}`), {
      target: { value: "delete 2" },
    });
    await act(async () => {
      fireEvent.click(both);
    });
    expect(deleteDid.mock.calls.map((c) => c[0])).toEqual(["alice", "carol"]);
    expect(deleteAcl).toHaveBeenCalledWith(OWNER);
    expect(onClose).toHaveBeenCalled();
  });

  it("keeps the entry and lists the failures when a delete fails part-way", async () => {
    listDids.mockResolvedValue([rec("alice"), rec("carol")]);
    deleteDid.mockImplementation(async (m) => {
      if (m === "carol") throw new Error("permission denied");
    });
    const { onClose } = await renderDialog();
    fireEvent.change(screen.getByLabelText(/To delete the DIDs too/), {
      target: { value: "delete 2" },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Remove access and delete 2 DIDs" }));
    });
    expect(deleteAcl).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toMatch(
      /1 DID could not be deleted, so did:web:bob.example keeps its access/,
    );
    expect(screen.getByText("deleted")).toBeTruthy();
    expect(screen.getByText("failed")).toBeTruthy();
    expect(screen.getByText("permission denied")).toBeTruthy();

    // Retrying deletes only what is left, then removes the entry.
    deleteDid.mockResolvedValue(undefined);
    deleteDid.mockClear();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Retry the failed ones" }));
    });
    expect(deleteDid.mock.calls.map((c) => c[0])).toEqual(["carol"]);
    expect(deleteAcl).toHaveBeenCalledWith(OWNER);
    expect(onClose).toHaveBeenCalled();
  });

  it("still offers removing access when the owned DIDs cannot be listed", async () => {
    listDids.mockRejectedValue(new Error("timeout"));
    await renderDialog();
    expect(screen.getByRole("alert").textContent).toMatch(/they will be kept/);
    expect(screen.getByRole("button", { name: "Remove access only" })).toBeTruthy();
  });
});
