// @vitest-environment jsdom
/**
 * Session expiry versus sign-out: an expired session is flagged and keeps its
 * claims (so the page under the prompt renders as before); signing out
 * clears both.
 */

import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const payload = { role: "admin", sub: "did:example:admin" };
vi.mock("../../lib/api", () => ({
  api: { logout: vi.fn(async () => {}) },
  decodeJwtPayload: () => payload,
  getToken: () => "saved-token",
  listenForSignOut: () => () => {},
  restoreSession: async () => {},
  setToken: vi.fn(),
}));

import { AuthProvider, useAuth } from "../AuthProvider";

function Probe() {
  const a = useAuth();
  return (
    <>
      <span>{`auth:${a.isAuthenticated} expired:${a.sessionExpired} role:${a.role}`}</span>
      <button onClick={a.logout}>out</button>
    </>
  );
}

afterEach(cleanup);

describe("AuthProvider", () => {
  it("flags an expired session and keeps its role until sign-out", async () => {
    await act(async () => {
      render(
        <AuthProvider>
          <Probe />
        </AuthProvider>,
      );
    });
    expect(screen.getByText("auth:true expired:false role:admin")).toBeTruthy();

    act(() => {
      window.dispatchEvent(new Event("webvh:unauthorized"));
    });
    expect(screen.getByText("auth:false expired:true role:admin")).toBeTruthy();

    act(() => {
      screen.getByText("out").click();
    });
    expect(screen.getByText("auth:false expired:false role:null")).toBeTruthy();
  });
});
