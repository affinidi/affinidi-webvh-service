// @vitest-environment jsdom
/**
 * The shared primitives: what they say to assistive technology, and what the
 * copy button does when the clipboard refuses.
 */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const setStringAsync = vi.fn<(value: string) => Promise<boolean>>();
vi.mock("expo-clipboard", () => ({ setStringAsync: (v: string) => setStringAsync(v) }));

import { Button } from "../Button";
import { COPY_FAILED, CopyButton } from "../CopyButton";
import { Field } from "../Field";
import { Heading } from "../Heading";
import { SegmentedControl } from "../SegmentedControl";

afterEach(() => {
  cleanup();
  setStringAsync.mockReset();
});

describe("Button", () => {
  it("is a named button that reports disabled and busy", () => {
    const onPress = vi.fn();
    render(<Button label="Save" busy onPress={onPress} />);
    const button = screen.getByRole("button", { name: "Save" });
    expect(button.getAttribute("aria-busy")).toBe("true");
    expect(button.getAttribute("aria-disabled")).toBe("true");
  });

  it("is reachable by keyboard", () => {
    render(<Button label="Go" onPress={() => {}} />);
    expect(screen.getByRole("button", { name: "Go" }).getAttribute("tabindex")).toBe("0");
  });
});

describe("Heading", () => {
  it("renders a heading with its level", () => {
    render(<Heading level={2}>Domains</Heading>);
    expect(screen.getByRole("heading", { level: 2, name: "Domains" })).toBeTruthy();
  });
});

describe("SegmentedControl", () => {
  it("is a radiogroup whose options announce checked", () => {
    const onChange = vi.fn();
    render(
      <SegmentedControl
        label="Role"
        value="owner"
        onChange={onChange}
        options={[
          { value: "admin", label: "Admin" },
          { value: "owner", label: "Owner" },
        ]}
      />,
    );
    expect(screen.getByRole("radiogroup", { name: "Role" })).toBeTruthy();
    expect(screen.getByRole("radio", { name: "Owner" }).getAttribute("aria-checked")).toBe("true");
    expect(screen.getByRole("radio", { name: "Admin" }).getAttribute("aria-checked")).toBe("false");
  });
});

describe("Field", () => {
  it("labels its input and submits on Enter", () => {
    const onSubmit = vi.fn();
    render(<Field label="Claim code" value="" onChangeText={() => {}} onSubmit={onSubmit} />);
    const input = screen.getByLabelText("Claim code");
    fireEvent.keyDown(input, { key: "Enter", code: "Enter" });
    fireEvent.keyPress(input, { key: "Enter", code: "Enter", charCode: 13 });
    expect(onSubmit).toHaveBeenCalled();
  });

  it("marks an error as invalid and announces it", () => {
    render(<Field label="DID" value="" onChangeText={() => {}} error="Not a DID" />);
    expect(screen.getByLabelText("DID").getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByRole("alert").textContent).toBe("Not a DID");
  });
});

describe("CopyButton", () => {
  it("says Copied after a successful copy", async () => {
    setStringAsync.mockResolvedValue(true);
    render(<CopyButton value="did:example:1" accessibilityLabel="Copy DID" />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy DID" }));
    });
    expect(setStringAsync).toHaveBeenCalledWith("did:example:1");
    expect(screen.getAllByText("Copied").length).toBeGreaterThan(0);
    expect(screen.queryByText(COPY_FAILED)).toBeNull();
  });

  it("says so when the clipboard refuses, and shows the value to copy by hand", async () => {
    setStringAsync.mockRejectedValue(new Error("NotAllowedError"));
    render(<CopyButton value="https://example.com/enroll#token=abc" label="Copy Link" />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy Link" }));
    });
    expect(screen.getByRole("alert").textContent).toBe(COPY_FAILED);
    expect(screen.getByText("https://example.com/enroll#token=abc")).toBeTruthy();
    // Still the copy button — not a false "Copied".
    expect(screen.getByRole("button", { name: "Copy Link" }).textContent).toBe("Copy Link");
  });
});
