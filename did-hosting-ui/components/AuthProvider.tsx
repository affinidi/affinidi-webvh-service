import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import {
  api,
  decodeJwtPayload,
  getToken,
  listenForSignOut,
  restoreSession,
  setToken as storeToken,
} from "../lib/api";
import { clearQueryCache } from "../lib/query";

interface AuthState {
  token: string | null;
  role: "admin" | "owner" | null;
  did: string | null;
  isAuthenticated: boolean;
  /** The saved session has been looked for, so `isAuthenticated: false`
   *  means signed out rather than not known yet. */
  restored: boolean;
  login: (token: string) => void;
  logout: () => void;
}

/** Decode the JWT payload (no verification) to extract claims. */
function decodeJwtClaims(token: string): { role: "admin" | "owner" | null; did: string | null } {
  const claims = decodeJwtPayload(token);
  const role = claims?.role === "admin" || claims?.role === "owner" ? claims.role : null;
  const did = typeof claims?.sub === "string" ? claims.sub : null;
  return { role, did };
}

const AuthContext = createContext<AuthState>({
  token: null,
  role: null,
  did: null,
  isAuthenticated: false,
  restored: false,
  login: () => {},
  logout: () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setTokenState] = useState<string | null>(null);
  const [restored, setRestored] = useState(false);

  useEffect(() => {
    // The token cache lives in memory, restored from IndexedDB — on a fresh
    // page load nothing has populated it yet.
    let cancelled = false;
    void (async () => {
      try {
        await restoreSession();
      } finally {
        if (!cancelled) {
          const saved = getToken();
          if (saved) setTokenState(saved);
          setRestored(true);
        }
      }
    })();

    // Clear React state when the API client detects an expired/invalid token
    const onUnauthorized = () => setTokenState(null);
    window.addEventListener("webvh:unauthorized", onUnauthorized);
    // ...and when another tab signs this session out.
    const stopListening = listenForSignOut(() => setTokenState(null));
    return () => {
      cancelled = true;
      window.removeEventListener("webvh:unauthorized", onUnauthorized);
      stopListening();
    };
  }, []);

  const login = useCallback((t: string) => {
    storeToken(t);
    setTokenState(t);
  }, []);

  const claims = useMemo(
    () => (token ? decodeJwtClaims(token) : { role: null, did: null }),
    [token],
  );

  // Reads are cached per key, not per session: when the signed-in subject
  // changes (sign-out, or another account), drop what the last one loaded so
  // it is never painted for the next.
  useEffect(() => () => clearQueryCache(), [claims.did]);

  const logout = useCallback(() => {
    // Revoke at the control plane before the session key is dropped: the
    // revoke is signed with it. The screen signs out at once either way.
    setTokenState(null);
    void api.logout();
  }, []);

  return (
    <AuthContext.Provider
      value={{
        token,
        ...claims,
        isAuthenticated: !!token,
        restored,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
