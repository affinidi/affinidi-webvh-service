/**
 * Domain context — fetches the caller-scoped domain list once on
 * mount + tracks the active "current domain" selection.
 *
 * Design (v0.7):
 * - Admins call `GET /api/domains` and see every configured domain.
 * - Non-admins call `GET /api/me/domains` and see only the subset
 *   their ACL `DomainScope` allows.
 * - The response carries a `default` field. We seed `currentDomain`
 *   from localStorage if the user previously picked one, else
 *   fall back to the API-supplied default.
 * - "All domains" is an Admin-only pseudo-selection — represented
 *   as `null` in `currentDomain` — used by the dashboard and DID
 *   list to surface every domain at once.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useApi } from "./ApiProvider";
import { useAuth } from "./AuthProvider";
import type { DomainEntry } from "../lib/api";

const STORAGE_KEY = "didhosting_current_domain";

interface DomainContextValue {
  /** Every domain the caller can see. Filtered by ACL scope when
   * the caller is not an Admin. Sorted by name for stable UI. */
  domains: DomainEntry[];
  /** Domain currently selected in the UI. `null` means "All domains"
   * (Admin-only) — the active selection used by filterable views. */
  currentDomain: string | null;
  /** Set the current selection. Pass `null` for "All domains"
   * (Admin only — callers should hide that affordance from
   * non-admins). Persisted to localStorage. */
  setCurrentDomain: (name: string | null) => void;
  /** Whether `domains` came back from the API. UI shows a spinner
   * placeholder until this flips true. */
  loaded: boolean;
  /** Last load error, if any. */
  error: string | null;
  /** The system default (or the caller's ACL default for
   * `AllowedWithDefault` scope). Used as the initial selection
   * when the user hasn't pinned one. */
  defaultDomain: string | null;
  /** Force a re-fetch (after create/disable/enable/set-default). */
  refresh: () => Promise<void>;
}

const DomainContext = createContext<DomainContextValue | null>(null);

function readStoredDomain(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStoredDomain(name: string | null): void {
  try {
    if (name === null) localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, name);
  } catch {
    // localStorage unavailable (e.g. native build); soft-fail.
  }
}

export function DomainProvider({ children }: { children: ReactNode }) {
  const api = useApi();
  const { isAuthenticated, role } = useAuth();
  const [domains, setDomains] = useState<DomainEntry[]>([]);
  const [defaultDomain, setDefaultDomain] = useState<string | null>(null);
  const [currentDomain, setCurrentDomainState] = useState<string | null>(() =>
    readStoredDomain(),
  );
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!isAuthenticated) {
      setDomains([]);
      setDefaultDomain(null);
      setLoaded(false);
      return;
    }
    try {
      // Admin → full list; Owner / Service → scoped subset.
      const fetcher =
        role === "admin" ? api.listDomains : api.listMyDomains;
      const resp = await fetcher();
      const sorted = [...resp.domains].sort((a, b) =>
        a.name.localeCompare(b.name),
      );
      setDomains(sorted);
      setDefaultDomain(resp.default);
      setError(null);
      setLoaded(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "failed to load domains";
      setError(msg);
      setLoaded(true);
    }
  }, [api, isAuthenticated, role]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // After the list loads, validate the stored selection still
  // exists in the current set. If the user pinned a domain that's
  // been deleted / disabled / removed-from-their-scope, fall back
  // to the API default. This protects against stale localStorage.
  useEffect(() => {
    if (!loaded || domains.length === 0) return;
    if (currentDomain === null && role === "admin") return; // "All" valid
    if (currentDomain && domains.some((d) => d.name === currentDomain)) {
      return;
    }
    // Fall back to the API default, or the first domain, or null.
    const next =
      defaultDomain && domains.some((d) => d.name === defaultDomain)
        ? defaultDomain
        : (domains[0]?.name ?? null);
    setCurrentDomainState(next);
    writeStoredDomain(next);
  }, [loaded, domains, currentDomain, defaultDomain, role]);

  const setCurrentDomain = useCallback((name: string | null) => {
    setCurrentDomainState(name);
    writeStoredDomain(name);
  }, []);

  const value = useMemo<DomainContextValue>(
    () => ({
      domains,
      currentDomain,
      setCurrentDomain,
      loaded,
      error,
      defaultDomain,
      refresh,
    }),
    [
      domains,
      currentDomain,
      setCurrentDomain,
      loaded,
      error,
      defaultDomain,
      refresh,
    ],
  );

  return (
    <DomainContext.Provider value={value}>{children}</DomainContext.Provider>
  );
}

export function useDomains(): DomainContextValue {
  const ctx = useContext(DomainContext);
  if (!ctx) {
    throw new Error("useDomains must be used inside <DomainProvider>");
  }
  return ctx;
}
