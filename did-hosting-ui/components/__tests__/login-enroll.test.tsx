// @vitest-environment jsdom
/**
 * Smoke tests for the sign-in and enrolment screens: they render, label their
 * controls, submit from the keyboard, and show what went wrong.
 */

import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const replace = vi.fn();
let searchParams: Record<string, string> = {};
vi.mock("expo-router", () => ({
  useRouter: () => ({ replace, push: vi.fn() }),
  useLocalSearchParams: () => searchParams,
}));
vi.mock("expo-clipboard", () => ({ setStringAsync: vi.fn(async () => true) }));

const login = vi.fn();
vi.mock("../AuthProvider", () => ({
  useAuth: () => ({ isAuthenticated: false, restored: true, login, logout: vi.fn() }),
}));

// The wallet sign-in widget runs its own trigger-link protocol (tested in
// lib/__tests__/oob-sign-in.test.ts); here it is just a placeholder.
vi.mock("../WalletSignIn", () => ({ WalletSignIn: () => <span>wallet sign-in</span> }));

vi.mock("../../lib/sign-in-readiness", () => ({
  fetchSignInReadiness: vi.fn(async () => ({ kind: "ready" })),
  offersWalletSignIn: () => true,
  notSetUpNote: () => null,
}));

vi.mock("../../lib/wallet", () => ({
  isWalletAvailable: () => false,
  isWalletProxyAvailable: () => false,
  listProxyCandidates: vi.fn(),
  loginWithWallet: vi.fn(),
  loginWithWalletProxy: vi.fn(),
  resolveProxyEntry: vi.fn(),
}));

const passkeyLoginStart = vi.fn();
const passkeyLoginFinish = vi.fn();
vi.mock("../../lib/api", () => ({
  api: {
    serverInfo: vi.fn(async () => ({
      serviceDid: "did:webvh:QmS:control.example.com",
      serviceNames: [],
    })),
    passkeyLoginStart: (...a: unknown[]) => passkeyLoginStart(...a),
    passkeyLoginFinish: (...a: unknown[]) => passkeyLoginFinish(...a),
  },
  setAuthMethod: vi.fn(),
  setRefreshToken: vi.fn(),
}));

const getPasskeyCredential = vi.fn();
vi.mock("../../lib/passkey", () => ({
  getPasskeyCredential: (...a: unknown[]) => getPasskeyCredential(...a),
  createPasskeyCredential: vi.fn(),
}));

const startRedemption = vi.fn();
vi.mock("../../lib/enrol-flow", () => ({
  startRedemption: (...a: unknown[]) => startRedemption(...a),
  completeRedemption: vi.fn(),
  describePurpose: (p: string) => (p === "session" ? "used to sign in" : "used to step up"),
  formatClaimCode: (v: string) => v,
}));

vi.mock("../../lib/address-bar", () => ({
  readPageParam: () => null,
  stripPageParam: vi.fn(),
  setNoReferrer: vi.fn(),
}));

import Enroll from "../../app/enroll";
import Login from "../../app/login";

beforeEach(() => {
  searchParams = {};
});
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

/** Press Enter in a react-native-web TextInput. */
function pressEnter(input: HTMLElement) {
  fireEvent.keyDown(input, { key: "Enter", code: "Enter", keyCode: 13 });
}

describe("login", () => {
  it("renders the sign-in options and the server's DID", async () => {
    await act(async () => {
      render(<Login />);
    });
    expect(screen.getByRole("heading", { level: 1, name: "Sign in" })).toBeTruthy();
    expect(screen.getByText("wallet sign-in")).toBeTruthy();
    expect(screen.getByText("did:webvh:QmS:control.example.com")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy this service's DID" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sign in with a passkey" })).toBeTruthy();
    const older = screen.getByRole("button", { name: "Using an older wallet?" });
    expect(older.getAttribute("aria-expanded")).toBe("false");
  });

  it("shows why a passkey login failed", async () => {
    passkeyLoginStart.mockRejectedValue(new Error("Passkeys are not configured here"));
    await act(async () => {
      render(<Login />);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in with a passkey" }));
    });
    expect(screen.getByRole("alert").textContent).toBe("Passkeys are not configured here");
    expect(login).not.toHaveBeenCalled();
  });

  it("says a dismissed passkey prompt was cancelled, not a raw WebAuthn error", async () => {
    passkeyLoginStart.mockResolvedValue({ authId: "a1", options: {} });
    getPasskeyCredential.mockRejectedValue(
      Object.assign(new Error("The operation either timed out or was not allowed."), {
        name: "NotAllowedError",
      }),
    );
    await act(async () => {
      render(<Login />);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in with a passkey" }));
    });
    expect(screen.getByRole("alert").textContent).toBe(
      "Passkey prompt was cancelled or timed out.",
    );
  });

  it("returns to the page named by ?next= after signing in", async () => {
    searchParams = { next: "/dids/alice" };
    passkeyLoginStart.mockResolvedValue({ authId: "a1", options: {} });
    getPasskeyCredential.mockResolvedValue({ id: "c" });
    passkeyLoginFinish.mockResolvedValue({ accessToken: "AT", refreshToken: "RT" });
    await act(async () => {
      render(<Login />);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in with a passkey" }));
    });
    expect(replace).toHaveBeenCalledWith("/dids/alice");
  });

  it("ignores a ?next= that points off this origin", async () => {
    searchParams = { next: "//evil.example/steal" };
    passkeyLoginStart.mockResolvedValue({ authId: "a1", options: {} });
    getPasskeyCredential.mockResolvedValue({ id: "c" });
    passkeyLoginFinish.mockResolvedValue({ accessToken: "AT", refreshToken: "RT" });
    await act(async () => {
      render(<Login />);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in with a passkey" }));
    });
    expect(replace).toHaveBeenCalledWith("/");
  });

  it("starts a passkey login from Enter in the DID field", async () => {
    passkeyLoginStart.mockResolvedValue({ authId: "a1", options: {} });
    getPasskeyCredential.mockResolvedValue({ id: "c" });
    passkeyLoginFinish.mockResolvedValue({ accessToken: "AT", refreshToken: "RT" });
    await act(async () => {
      render(<Login />);
    });
    const field = screen.getByLabelText(
      "Your DID, to sign in with a security key the browser does not offer",
    );
    fireEvent.change(field, { target: { value: "did:example:me" } });
    await act(async () => {
      pressEnter(field);
    });
    expect(passkeyLoginStart).toHaveBeenCalledWith("did:example:me");
    expect(login).toHaveBeenCalledWith("AT");
    expect(replace).toHaveBeenCalledWith("/");
  });
});

describe("enroll", () => {
  it("asks for the enrolment link when it carries no token, without calling it a failure", () => {
    render(<Enroll />);
    expect(screen.getByRole("heading", { name: "Open your enrolment link" })).toBeTruthy();
    expect(screen.getByText(/no invite token/)).toBeTruthy();
    expect(screen.queryByText(/Failed/)).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("asks for the claim code and submits it on Enter", async () => {
    searchParams = { token: "tok" };
    startRedemption.mockResolvedValue({
      enrollmentId: "e1",
      subject: "did:example:invitee",
      purpose: "session",
      options: {},
    });
    render(<Enroll />);
    expect(screen.getByRole("heading", { name: "Register a Passkey" })).toBeTruthy();
    const code = screen.getByLabelText("Claim code");
    const cont = screen.getByRole("button", { name: "Continue" });
    expect(cont.getAttribute("aria-disabled")).toBe("true");
    fireEvent.change(code, { target: { value: "ABCD-EFGH-IJKL" } });
    await act(async () => {
      pressEnter(code);
    });
    expect(startRedemption).toHaveBeenCalledWith("tok", "ABCD-EFGH-IJKL");
    expect(screen.getByRole("heading", { name: "Confirm Your Passkey" })).toBeTruthy();
    expect(screen.getByText("did:example:invitee")).toBeTruthy();
  });

  it("shows a refused claim code as the field's error", async () => {
    searchParams = { token: "tok" };
    startRedemption.mockRejectedValue(new Error("That claim code is not right."));
    render(<Enroll />);
    const code = screen.getByLabelText("Claim code");
    fireEvent.change(code, { target: { value: "WRONG" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    });
    expect(screen.getByRole("alert").textContent).toBe("That claim code is not right.");
    expect(code.getAttribute("aria-invalid")).toBe("true");
  });
});
