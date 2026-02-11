import React, { createContext, useContext, useState, useCallback, useEffect } from "react";
import { getToken, setToken as storeToken, clearToken } from "../lib/api";

interface AuthState {
  token: string | null;
  role: "admin" | "owner" | null;
  isAuthenticated: boolean;
  login: (token: string) => void;
  logout: () => void;
}

/** Decode the JWT payload (no verification) to extract the role claim. */
function decodeJwtRole(token: string): "admin" | "owner" | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const json = JSON.parse(atob(payload));
    if (json.role === "admin" || json.role === "owner") return json.role;
    return null;
  } catch {
    return null;
  }
}

const AuthContext = createContext<AuthState>({
  token: null,
  role: null,
  isAuthenticated: false,
  login: () => {},
  logout: () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setTokenState] = useState<string | null>(null);

  useEffect(() => {
    const saved = getToken();
    if (saved) setTokenState(saved);

    // Clear React state when the API client detects an expired/invalid token
    const onUnauthorized = () => setTokenState(null);
    window.addEventListener("webvh:unauthorized", onUnauthorized);
    return () => window.removeEventListener("webvh:unauthorized", onUnauthorized);
  }, []);

  const login = useCallback((t: string) => {
    storeToken(t);
    setTokenState(t);
  }, []);

  const logout = useCallback(() => {
    clearToken();
    setTokenState(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ token, role: token ? decodeJwtRole(token) : null, isAuthenticated: !!token, login, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
