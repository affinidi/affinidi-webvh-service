/** VTI browser-extension wallet bridge.
 *
 * On web, the wallet extension injects `window.vtaWallet` into pages matching
 * its `host_permissions`. This module is the UI-side feature-detect + a thin
 * wrapper that asks the wallet to log into THIS did-hosting server.
 *
 * The wallet's SIOPv2 path round-trips against `${baseUrl}/auth/challenge` and
 * `${baseUrl}/auth/` — the exact endpoints did-hosting-control exposes — and
 * returns a server-issued bearer token. That token is fed into
 * `AuthProvider.login(...)` identically to the passkey path; both yield the
 * same JWT shape, so nothing else in the UI needs to know which path was taken.
 *
 * Native (iOS / Android) builds never see `window.vtaWallet`; the helper
 * degrades gracefully via `isWalletAvailable()`.
 */

import { Platform } from "react-native";

/** A subset of the wallet provider's interface — just the SIOPv2 login.
 *  Declaring it inline keeps did-hosting-ui from depending on the extension
 *  package. The full interface lives in `@pnm/extension/provider.ts`. */
interface VtaWalletLoginParams {
  rpDid: string;
  baseUrl: string;
}
export interface VtaWalletLoginResult {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  holderDid: string;
}
interface VtaWalletSignTrustTaskParams {
  envelope: Record<string, unknown>;
}
interface VtaWalletSignTrustTaskResult {
  signedEnvelope: Record<string, unknown>;
  holderDid: string;
}
interface VtaWalletProvider {
  login(params: VtaWalletLoginParams): Promise<VtaWalletLoginResult>;
  /** Sign a Trust-Task envelope with the wallet's holder did:peer #key-2.
   *  The caller sets `recipient` (audience) on the envelope before calling;
   *  the wallet adds an `eddsa-jcs-2022` Data Integrity proof and returns the
   *  envelope. Server verifies by resolving the did:peer. */
  signTrustTask?(
    params: VtaWalletSignTrustTaskParams,
  ): Promise<VtaWalletSignTrustTaskResult>;
}
declare global {
  interface Window {
    vtaWallet?: VtaWalletProvider;
  }
}

/** True iff this is a web build AND the wallet extension has injected its
 *  provider into the page. False on iOS/Android or when the extension is
 *  missing — callers should hide the wallet button + show an install hint. */
export function isWalletAvailable(): boolean {
  return (
    Platform.OS === "web" &&
    typeof window !== "undefined" &&
    typeof window.vtaWallet?.login === "function"
  );
}

/** The RP DID the wallet signs the SIOPv2 `id_token` for. Reads
 *  `EXPO_PUBLIC_RP_DID` at build time; defaults to the demo VTA so a
 *  fresh checkout works without env-var plumbing. Operators with their own
 *  VTA set the env var. */
export function getRpDid(): string {
  return (
    process.env.EXPO_PUBLIC_RP_DID ??
    "did:webvh:QmUcydmZKWsAUcuAGzyQRjXnSvnMdSRF1YM7gyhugYGS9s:webvh.storm.ws"
  );
}

/** API base for the wallet's SIOPv2 round-trip. The UI is served same-origin
 *  with the did-hosting-control API at `/api`, so the default resolves the
 *  wallet's `${baseUrl}/auth/challenge` to the right endpoint without
 *  configuration. Override with `EXPO_PUBLIC_API_BASE` if the API is on a
 *  separate origin. */
export function getApiBase(): string {
  if (process.env.EXPO_PUBLIC_API_BASE) return process.env.EXPO_PUBLIC_API_BASE;
  return (typeof window !== "undefined" ? window.location.origin : "") + "/api";
}

/** Trigger the wallet's SIOPv2 login. Resolves to the result containing the
 *  server-issued access token (suitable for `AuthProvider.login`); rejects
 *  if the wallet isn't available, the user denies the consent prompt, or the
 *  server rejects the `id_token`. */
export async function loginWithWallet(): Promise<VtaWalletLoginResult> {
  if (!isWalletAvailable()) {
    throw new Error(
      "VTI wallet extension is not installed (or this isn't running in a web browser).",
    );
  }
  return window.vtaWallet!.login({
    rpDid: getRpDid(),
    baseUrl: getApiBase(),
  });
}
