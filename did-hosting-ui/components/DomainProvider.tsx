/**
 * Domain context — reads the caller-scoped domain list (cached, see
 * `lib/query.ts`) + tracks the active "current domain" selection.
 *
 * Design (v0.7):
 * - Admins send `domain/list` and see every configured domain.
 * - Non-admins send `me/domains` and see only the subset
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
import { errorMessage } from "../lib/errors";
import { useTrustTaskQuery } from "../lib/query";

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

/** The query key the domain list is cached under. A domain mutation
 *  invalidates the `["domains"]` prefix. */
export const DOMAINS_KEY = ["domains"] as const;

export function DomainProvider({ children }: { children: ReactNode }) {
  const api = useApi();
  const { isAuthenticated, role } = useAuth();
  const [currentDomain, setCurrentDomainState] = useState<string | null>(() => readStoredDomain());

  // Admin → full list; Owner / Service → scoped subset. The role is in the
  // key, so a different session's list is never read from the cache.
  const query = useTrustTaskQuery(
    [...DOMAINS_KEY, role === "admin" ? "all" : "mine"],
    () => (role === "admin" ? api.listDomains() : api.listMyDomains()),
    { enabled: isAuthenticated },
  );
  const resp = isAuthenticated ? query.data : undefined;
  // Sorted once per answer, so the array is stable between renders and the
  // fallback effect below does not re-run for nothing.
  const domains = useMemo<DomainEntry[]>(
    () => (resp ? [...resp.domains].sort((a, b) => a.name.localeCompare(b.name)) : []),
    [resp],
  );
  const defaultDomain = resp?.default ?? null;
  const loaded = isAuthenticated && !query.loading && (resp !== undefined || query.error != null);
  const error =
    isAuthenticated && query.error ? errorMessage(query.error, "failed to load domains") : null;
  const { refetch } = query;
  const refresh = useCallback(() => refetch(), [refetch]);

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
    [domains, currentDomain, setCurrentDomain, loaded, error, defaultDomain, refresh],
  );

  return <DomainContext.Provider value={value}>{children}</DomainContext.Provider>;
}

export function useDomains(): DomainContextValue {
  const ctx = useContext(DomainContext);
  if (!ctx) {
    throw new Error("useDomains must be used inside <DomainProvider>");
  }
  return ctx;
}
