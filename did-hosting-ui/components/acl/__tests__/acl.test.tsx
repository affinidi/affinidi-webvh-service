// @vitest-environment jsdom
/**
 * The Access Control pieces: the scope editor speaks radiogroup, and a row's
 * save hands back the entry as it was loaded, so `updateAcl` can diff.
 */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("expo-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <>{children}</>,
}));
vi.mock("expo-clipboard", () => ({ setStringAsync: vi.fn() }));

import type { AclEntry } from "../../../lib/api";
import { AclEntryRow, type EditState } from "../AclEntryRow";
import { ScopeEditor } from "../ScopeEditor";

afterEach(cleanup);

const ENTRY: AclEntry = {
  did: "did:web:bob.example",
  role: "owner",
  label: "Bob",
  created_at: 1_700_000_000,
  max_total_size: null,
  max_did_count: 5,
  domains: { kind: "allowed", domains: ["a.example"] },
};

const noop = () => {};

describe("ScopeEditor", () => {
  it("offers the scope kinds as a radiogroup and the domains as toggles", () => {
    const onChange = vi.fn();
    render(
      <ScopeEditor
        draft={{ kind: "allowed", domains: ["a.example"], default: "" }}
        availableDomains={[
          { name: "a.example", disabled: false },
          { name: "b.example", disabled: false },
        ]}
        onChange={onChange}
      />,
    );
    expect(screen.getByRole("radiogroup", { name: "Domain scope" })).toBeTruthy();
    expect(screen.getByRole("radio", { name: "Specific" }).getAttribute("aria-checked")).toBe(
      "true",
    );
    expect(screen.getByRole("button", { name: "a.example" }).getAttribute("aria-pressed")).toBe(
      "true",
    );
    fireEvent.click(screen.getByRole("button", { name: "b.example" }));
    expect(onChange).toHaveBeenCalledWith({
      kind: "allowed",
      domains: ["a.example", "b.example"],
      default: "",
    });
  });
});

describe("AclEntryRow", () => {
  const editing: EditState = {
    did: ENTRY.did,
    role: "owner",
    label: "Bob",
    maxTotalSize: "",
    maxDidCount: "5",
    scope: { kind: "allowed", domains: ["a.example"], default: "" },
  };

  const row = (onSave: (e: AclEntry) => void) =>
    render(
      <AclEntryRow
        item={ENTRY}
        editing={editing}
        saving={false}
        availableDomains={[{ name: "a.example", disabled: false }]}
        onStartEdit={noop}
        onCancelEdit={noop}
        onSave={onSave}
        onDelete={noop}
        onChangeRole={noop}
        onChangeLabel={noop}
        onChangeMaxTotalSize={noop}
        onChangeMaxDidCount={noop}
        onChangeScope={noop}
        passkeysExpanded={false}
        onTogglePasskeys={noop}
      />,
    );

  it("labels its inputs and saves with the entry as loaded", async () => {
    const onSave = vi.fn();
    row(onSave);
    expect(screen.getByLabelText("Label")).toBeTruthy();
    expect(screen.getByRole("radiogroup", { name: "Role" })).toBeTruthy();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
    });
    expect(onSave).toHaveBeenCalledWith(ENTRY);
  });

  it("saves on Enter in a field", () => {
    const onSave = vi.fn();
    row(onSave);
    const input = screen.getByLabelText("Max DIDs");
    fireEvent.keyDown(input, { key: "Enter", code: "Enter" });
    fireEvent.keyPress(input, { key: "Enter", code: "Enter", charCode: 13 });
    expect(onSave).toHaveBeenCalledWith(ENTRY);
  });
});
