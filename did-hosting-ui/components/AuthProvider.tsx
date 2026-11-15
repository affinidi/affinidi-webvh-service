import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
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
  /** The session ended under the operator (expired, revoked, key lost) rather
   *  than by signing out: the screen stays mounted under a sign-in prompt so
   *  unsaved work is not thrown away. */
  sessionExpired: boolean;
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
  sessionExpired: false,
  login: () => {},
  logout: () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setTokenState] = useState<string | null>(null);
  const [restored, setRestored] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);
  // The token as of the last change, for handlers registered once.
  const tokenRef = useRef<string | null>(null);

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
          if (saved) {
            tokenRef.current = saved;
            setTokenState(saved);
          }
          setRestored(true);
        }
      }
    })();

    // The API client found the session gone (expired, revoked, key lost).
    // Only a session that was held can expire; a refused anonymous read says
    // nothing about one.
    const onUnauthorized = () => {
      if (tokenRef.current) setSessionExpired(true);
      tokenRef.current = null;
      setTokenState(null);
    };
    window.addEventListener("webvh:unauthorized", onUnauthorized);
    // Another tab signed this session out: that was deliberate, so this tab
    // signs out too rather than offering to sign back in.
    const stopListening = listenForSignOut(() => {
      tokenRef.current = null;
      setTokenState(null);
      setSessionExpired(false);
      clearQueryCache();
    });
    return () => {
      cancelled = true;
      window.removeEventListener("webvh:unauthorized", onUnauthorized);
      stopListening();
    };
  }, []);

  const login = useCallback((t: string) => {
    storeToken(t);
    tokenRef.current = t;
    setTokenState(t);
    setSessionExpired(false);
  }, []);

  // While a session has expired, the screen under the sign-in prompt keeps
  // rendering as it did — an admin page must not flip to its "admins only"
  // view and drop what was typed — so the last session's claims stay.
  // Nothing is sent with them: there is no token.
  const lastClaims = useRef<ReturnType<typeof decodeJwtClaims>>({ role: null, did: null });
  const claims = useMemo(() => {
    if (token) {
      lastClaims.current = decodeJwtClaims(token);
      return lastClaims.current;
    }
    return sessionExpired ? lastClaims.current : { role: null, did: null };
  }, [token, sessionExpired]);

  // Reads are cached per key, not per session: when a different subject signs
  // in, drop what the last one loaded so it is never painted for the next.
  // Not on expiry — the screen under the sign-in prompt keeps its data until
  // the same operator is back.
  const lastSubject = useRef<string | null>(null);
  useEffect(() => {
    if (!claims.did) return;
    if (lastSubject.current && lastSubject.current !== claims.did) clearQueryCache();
    lastSubject.current = claims.did;
  }, [claims.did]);

  const logout = useCallback(() => {
    // Revoke at the control plane before the session key is dropped: the
    // revoke is signed with it. The screen signs out at once either way.
    tokenRef.current = null;
    setTokenState(null);
    setSessionExpired(false);
    clearQueryCache();
    lastSubject.current = null;
    void api.logout();
  }, []);

  return (
    <AuthContext.Provider
      value={{
        token,
        ...claims,
        isAuthenticated: !!token,
        restored,
        sessionExpired,
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
