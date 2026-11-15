// @vitest-environment jsdom
/**
 * The in-app confirmation dialog and toasts that replaced `window.confirm` /
 * `window.alert`: labelled actions, focus on Cancel, type-to-confirm, more
 * than one action, and notices that say what happened.
 */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CONFIRMED,
  confirmAction,
  notify,
  resetFeedbackForTests,
  showMessage,
} from "../../lib/feedback";
import { FeedbackHost } from "../FeedbackHost";

afterEach(() => {
  act(() => resetFeedbackForTests());
  cleanup();
  vi.useRealTimers();
});

/** Open a dialog; the answer is wrapped so awaiting `open` does not wait for it. */
async function open(options: Parameters<typeof confirmAction>[0]) {
  let result!: Promise<string | null>;
  await act(async () => {
    result = confirmAction(options);
  });
  return { result };
}

describe("confirmation dialog", () => {
  it("names the action, and focuses Cancel rather than the destructive button", async () => {
    render(<FeedbackHost />);
    const { result } = await open({
      title: "Delete DID?",
      body: "This cannot be undone.",
      confirmLabel: "Delete DID",
    });
    expect(screen.getByRole("heading", { name: "Delete DID?" })).toBeTruthy();
    expect(screen.getByText("This cannot be undone.")).toBeTruthy();
    const cancel = screen.getByRole("button", { name: "Cancel" });
    expect(screen.getByRole("button", { name: "Delete DID" })).toBeTruthy();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(document.activeElement).toBe(cancel);
    await act(async () => {
      fireEvent.click(cancel);
    });
    await expect(result).resolves.toBeNull();
    expect(screen.queryByRole("heading", { name: "Delete DID?" })).toBeNull();
  });

  it("keeps the action disabled until the name is typed", async () => {
    render(<FeedbackHost />);
    const { result } = await open({
      title: "Purge example.com?",
      body: "Every DID on it is deleted.",
      confirmLabel: "Purge & delete",
      typeToConfirm: "example.com",
    });
    const action = screen.getByRole("button", { name: "Purge & delete" });
    expect(action.getAttribute("aria-disabled")).toBe("true");
    const field = screen.getByLabelText("Type example.com to confirm");
    fireEvent.change(field, { target: { value: "example.co" } });
    expect(action.getAttribute("aria-disabled")).toBe("true");
    fireEvent.change(field, { target: { value: "example.com" } });
    expect(action.getAttribute("aria-disabled")).not.toBe("true");
    await act(async () => {
      fireEvent.click(action);
    });
    await expect(result).resolves.toBe(CONFIRMED);
  });

  it("offers several actions and resolves with the one chosen", async () => {
    render(<FeedbackHost />);
    const { result } = await open({
      title: "Remove?",
      body: "Choose.",
      choices: [
        { value: "keep", label: "Remove access only", variant: "secondary" },
        { value: "all", label: "Remove and delete", requiresTyping: true },
      ],
      typeToConfirm: "delete 2",
    });
    expect(
      screen.getByRole("button", { name: "Remove and delete" }).getAttribute("aria-disabled"),
    ).toBe("true");
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Remove access only" }));
    });
    await expect(result).resolves.toBe("keep");
  });

  it("queues a second request until the first is answered", async () => {
    render(<FeedbackHost />);
    const { result: first } = await open({ title: "First?", body: "1" });
    const { result: second } = await open({ title: "Second?", body: "2" });
    expect(screen.getByRole("heading", { name: "First?" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Second?" })).toBeNull();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    });
    await expect(first).resolves.toBe(CONFIRMED);
    expect(screen.getByRole("heading", { name: "Second?" })).toBeTruthy();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    });
    await expect(second).resolves.toBeNull();
  });
});

describe("toasts", () => {
  it("announces success as a status that fades, and errors as alerts that stay", async () => {
    vi.useFakeTimers();
    render(<FeedbackHost />);
    act(() => {
      notify("success", "DID deleted", '"alice" has been deleted.');
      notify("error", "Could not delete", "permission denied");
    });
    expect(screen.getByRole("status").textContent).toMatch(/DID deleted/);
    expect(screen.getByRole("alert").textContent).toMatch(/Could not delete/);
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.getByRole("alert")).toBeTruthy();
    act(() => {
      fireEvent.click(screen.getByRole("button", { name: "Dismiss: Could not delete" }));
    });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("reads the kind off a card's (title, message) notice", () => {
    render(<FeedbackHost />);
    act(() => showMessage("Error", "Upload failed"));
    expect(screen.getByRole("alert").textContent).toMatch(/Upload failed/);
    act(() => showMessage("Success", "Uploaded"));
    expect(screen.getByRole("status").textContent).toMatch(/Uploaded/);
  });
});
