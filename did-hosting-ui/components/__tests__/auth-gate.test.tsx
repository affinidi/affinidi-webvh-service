// @vitest-environment jsdom
/**
 * The route guard: a splash while the session is restored, a redirect to the
 * sign-in page that remembers where the visitor was, and — when a session
 * expires mid-task — a prompt over the screen that leaves what was typed on
 * it alone.
 */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { TextInput } from "react-native";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const replace = vi.fn();
let pathname = "/dids/alice";
vi.mock("expo-router", () => ({
  usePathname: () => pathname,
  useRouter: () => ({ replace, push: vi.fn() }),
}));

let auth = {
  isAuthenticated: true,
  restored: true,
  sessionExpired: false,
  logout: vi.fn(),
  login: vi.fn(),
};
vi.mock("../AuthProvider", () => ({ useAuth: () => auth }));

// The panel has its own tests (login-enroll); here it only has to appear.
vi.mock("../SignInPanel", () => ({
  SignInPanel: ({ onSignedIn }: { onSignedIn: () => void }) => (
    <button onClick={onSignedIn}>sign-in panel</button>
  ),
}));

import { AuthGate } from "../AuthGate";
import { RequireAuth } from "../RequireAuth";

/** A screen with unsaved input, to see whether it survives. */
function Editor() {
  const [text, setText] = useState("");
  return <TextInput aria-label="Draft" value={text} onChangeText={setText} />;
}

function app() {
  return (
    <AuthGate>
      <RequireAuth purpose="edit">
        <Editor />
      </RequireAuth>
    </AuthGate>
  );
}

beforeEach(() => {
  pathname = "/dids/alice";
  auth = { ...auth, isAuthenticated: true, restored: true, sessionExpired: false };
  window.history.replaceState(null, "", "/dids/alice?tab=log");
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("AuthGate", () => {
  it("shows the splash, not a signed-out page, while the session is restored", () => {
    auth = { ...auth, isAuthenticated: false, restored: false };
    render(app());
    expect(screen.getByTestId("splash")).toBeTruthy();
    expect(screen.queryByText(/log in/i)).toBeNull();
    expect(replace).not.toHaveBeenCalled();
  });

  it("sends a signed-out visitor to sign in, returning to this page", () => {
    auth = { ...auth, isAuthenticated: false };
    render(app());
    expect(replace).toHaveBeenCalledWith("/login?next=%2Fdids%2Falice%3Ftab%3Dlog");
    expect(screen.queryByLabelText("Draft")).toBeNull();
  });

  it("leaves the public pages alone", () => {
    pathname = "/login";
    auth = { ...auth, isAuthenticated: false };
    render(
      <AuthGate>
        <span>login page</span>
      </AuthGate>,
    );
    expect(screen.getByText("login page")).toBeTruthy();
    expect(replace).not.toHaveBeenCalled();
  });

  it("keeps the screen and its unsaved input under a sign-in prompt when the session expires", () => {
    const { rerender } = render(app());
    fireEvent.change(screen.getByLabelText("Draft"), { target: { value: "half-written edit" } });

    auth = { ...auth, isAuthenticated: false, sessionExpired: true };
    rerender(app());

    expect(screen.getByRole("alert").textContent).toMatch(/Session expired — sign in again/);
    expect((screen.getByLabelText("Draft") as HTMLInputElement).value).toBe("half-written edit");
    expect(replace).not.toHaveBeenCalled();

    // Signing in again happens in place.
    act(() => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in again" }));
    });
    expect(screen.getByText("sign-in panel")).toBeTruthy();

    auth = { ...auth, isAuthenticated: true, sessionExpired: false };
    rerender(app());
    expect(screen.queryByTestId("session-expired")).toBeNull();
    expect((screen.getByLabelText("Draft") as HTMLInputElement).value).toBe("half-written edit");
  });
});
