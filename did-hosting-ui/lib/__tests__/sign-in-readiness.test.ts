/**
 * The login page's decision whether to offer wallet sign-in, from the
 * control plane's self-check (`GET /api/sign-in/readiness`).
 */

import { describe, expect, it } from "vitest";

import {
  fetchSignInReadiness,
  notSetUpNote,
  offersWalletSignIn,
  parseReadiness,
} from "../sign-in-readiness";

function fakeFetch(status: number, body: unknown): typeof fetch {
  return (async (url: string) => {
    expect(url).toBe("https://dids.example.org/api/sign-in/readiness");
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
}

const BASE = "https://dids.example.org/api";

describe("sign-in readiness", () => {
  it("offers wallet sign-in when every service is listed", async () => {
    const r = await fetchSignInReadiness(fakeFetch(200, { walletSignIn: "ready" }), BASE);
    expect(offersWalletSignIn(r)).toBe(true);
    expect(notSetUpNote(r)).toBeNull();
  });

  it("does not offer it, and says why, when services are missing", async () => {
    const r = await fetchSignInReadiness(
      fakeFetch(200, {
        walletSignIn: "not-set-up",
        missingServices: ["SignInPortal", "TrustTaskHTTPS"],
        missingRecommended: ["WebVHHosting"],
      }),
      BASE,
    );
    expect(offersWalletSignIn(r)).toBe(false);
    // The recommended service is not part of the note.
    expect(notSetUpNote(r)).toBe(
      "Wallet sign-in isn't set up on this server yet: its DID doesn't list " +
        "SignInPortal and TrustTaskHTTPS.",
    );
  });

  it("still offers it, with no note, when only WebVHHosting is missing", async () => {
    const r = await fetchSignInReadiness(
      fakeFetch(200, { walletSignIn: "ready", missingRecommended: ["WebVHHosting"] }),
      BASE,
    );
    expect(offersWalletSignIn(r)).toBe(true);
    expect(notSetUpNote(r)).toBeNull();
    expect(r).toEqual({ walletSignIn: "ready", missingRecommended: ["WebVHHosting"] });
  });

  it("does not let a recommended service alone hide sign-in", () => {
    // An answer naming only WebVHHosting as required is not a valid not-set-up.
    const r = parseReadiness({ walletSignIn: "not-set-up", missingServices: ["WebVHHosting"] });
    expect(offersWalletSignIn(r)).toBe(true);
  });

  it("lists only the missing services, in a fixed order", () => {
    expect(
      notSetUpNote(
        parseReadiness({ walletSignIn: "not-set-up", missingServices: ["TrustTaskHTTPS", "SignInPortal"] }),
      ),
    ).toBe(
      "Wallet sign-in isn't set up on this server yet: its DID doesn't list SignInPortal and TrustTaskHTTPS.",
    );
    expect(
      notSetUpNote(parseReadiness({ walletSignIn: "not-set-up", missingServices: ["TrustTaskHTTPS"] })),
    ).toBe("Wallet sign-in isn't set up on this server yet: its DID doesn't list TrustTaskHTTPS.");
  });

  it("still offers it when the check could not run", async () => {
    const r = await fetchSignInReadiness(fakeFetch(200, { walletSignIn: "unknown" }), BASE);
    expect(offersWalletSignIn(r)).toBe(true);
    expect(notSetUpNote(r)).toBeNull();
  });

  it("still offers it on an older control plane, a server error or a network failure", async () => {
    expect(offersWalletSignIn(await fetchSignInReadiness(fakeFetch(404, {}), BASE))).toBe(true);
    expect(offersWalletSignIn(await fetchSignInReadiness(fakeFetch(500, {}), BASE))).toBe(true);
    const failing = (async () => {
      throw new TypeError("network down");
    }) as unknown as typeof fetch;
    expect(offersWalletSignIn(await fetchSignInReadiness(failing, BASE))).toBe(true);
  });

  it("treats a malformed answer as unknown, and ignores names it does not know", () => {
    for (const body of [
      null,
      "ready",
      { walletSignIn: "not-set-up" },
      { walletSignIn: "not-set-up", missingServices: [] },
      { walletSignIn: "not-set-up", missingServices: ["<script>"] },
      { walletSignIn: "something-new" },
    ]) {
      expect(offersWalletSignIn(parseReadiness(body))).toBe(true);
    }
    expect(
      notSetUpNote(
        parseReadiness({ walletSignIn: "not-set-up", missingServices: ["SignInPortal", "Other"] }),
      ),
    ).toBe("Wallet sign-in isn't set up on this server yet: its DID doesn't list SignInPortal.");
  });
});
