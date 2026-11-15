/**
 * A small read cache for the console's Trust Task reads.
 *
 * Every screen used to repeat `useState(loading/error/data)` + `useEffect` +
 * `.catch`, fetch the same reads separately (the dashboard, the service
 * overview and settings each asked for `server/config`), and race: a quick
 * range switch could paint the answer to the range before. This is the one
 * place that does it:
 *
 * - **Dedup.** Readers of the same key share one cache entry and one request
 *   in flight.
 * - **Stale-while-revalidate.** A reader that mounts on a key already held
 *   sees that data at once, and the entry refetches behind it if it is older
 *   than `staleTime`.
 * - **Polling.** `refetchInterval` refetches on a timer through
 *   `startPolling` — skipped while the page is hidden, once on becoming
 *   visible, and sent as a background request that does not count as
 *   operator activity.
 * - **Stale-response guard.** Each fetch of an entry is numbered; only the
 *   latest one may write. A reader follows its *current* key, so a late answer
 *   for a key it has moved off is never shown.
 * - **Invalidation.** A mutation names the keys it changed
 *   (`invalidateQueries`); the readers on screen refetch, the rest are marked
 *   stale for their next mount.
 *
 * Keys are arrays (`["dids", owner]`); a prefix matches every key that starts
 * with it. The cache is cleared on sign-out (`clearQueryCache`), so one
 * session never paints another's data.
 */

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";

import { startPolling } from "./poll";

export type QueryKey = readonly unknown[];

/** Passed to a fetcher: `background` is set for timer-driven refetches, so
 *  the fetcher can hand it to an `api` read (`ReadOptions`). */
export interface FetchContext {
  background: boolean;
}

export type Fetcher<T> = (ctx: FetchContext) => Promise<T>;

interface Entry {
  key: QueryKey;
  data: unknown;
  hasData: boolean;
  error: unknown;
  /** When the data was last written, ms. 0 = never, or invalidated. */
  updatedAt: number;
  /** When data was last written — kept through invalidation, for display. */
  lastSuccessAt: number;
  inFlight: Promise<void> | null;
  /** Sequence of the newest fetch; an older one's answer is dropped. */
  seq: number;
  fetcher: Fetcher<unknown> | null;
  listeners: Set<() => void>;
  /** A fresh object per change, for `useSyncExternalStore`. */
  snapshot: QuerySnapshot<unknown>;
}

export interface QuerySnapshot<T> {
  data: T | undefined;
  error: unknown;
  /** No data yet and a fetch is running — show a spinner. */
  loading: boolean;
  /** A fetch is running over data already shown. */
  refreshing: boolean;
  /** When the data shown was last fetched, ms; `null` before the first. */
  updatedAt: number | null;
}

const cache = new Map<string, Entry>();

const EMPTY: QuerySnapshot<never> = Object.freeze({
  data: undefined,
  error: null,
  loading: false,
  refreshing: false,
  updatedAt: null,
});

function hashKey(key: QueryKey): string {
  return JSON.stringify(key);
}

function entryFor(key: QueryKey): Entry {
  const h = hashKey(key);
  let e = cache.get(h);
  if (!e) {
    e = {
      key,
      data: undefined,
      hasData: false,
      error: null,
      updatedAt: 0,
      lastSuccessAt: 0,
      inFlight: null,
      seq: 0,
      fetcher: null,
      listeners: new Set(),
      snapshot: EMPTY,
    };
    cache.set(h, e);
  }
  return e;
}

function publish(e: Entry): void {
  e.snapshot = {
    data: e.data,
    error: e.error,
    loading: !e.hasData && e.inFlight !== null,
    refreshing: e.hasData && e.inFlight !== null,
    updatedAt: e.hasData ? e.lastSuccessAt : null,
  };
  for (const l of [...e.listeners]) l();
}

/** Fetch `e` now unless a fetch is already running (dedup). */
function run(e: Entry, ctx: FetchContext, force = false): Promise<void> {
  if (e.inFlight && !force) return e.inFlight;
  const fetcher = e.fetcher;
  if (!fetcher) return Promise.resolve();
  const seq = ++e.seq;
  const p = (async () => {
    try {
      const data = await fetcher(ctx);
      if (seq !== e.seq) return; // a newer fetch owns the entry now
      e.data = data;
      e.hasData = true;
      e.error = null;
      e.updatedAt = Date.now();
      e.lastSuccessAt = e.updatedAt;
    } catch (err) {
      if (seq !== e.seq) return;
      // Keep the last good data: an error over stale data is still worth
      // showing the data for.
      e.error = err;
    } finally {
      if (seq === e.seq) {
        e.inFlight = null;
        publish(e);
      }
    }
  })();
  e.inFlight = p;
  publish(e);
  return p;
}

function matches(key: QueryKey, prefix: QueryKey): boolean {
  if (prefix.length > key.length) return false;
  return prefix.every((part, i) => JSON.stringify(part) === JSON.stringify(key[i]));
}

/**
 * Mark every entry whose key starts with one of `prefixes` stale, and refetch
 * those a mounted reader is showing. Resolves when those refetches settle.
 */
export function invalidateQueries(...prefixes: QueryKey[]): Promise<void> {
  const runs: Promise<void>[] = [];
  for (const e of cache.values()) {
    if (!prefixes.some((p) => matches(e.key, p))) continue;
    e.updatedAt = 0;
    if (e.listeners.size > 0) runs.push(run(e, { background: false }, true));
  }
  return Promise.all(runs).then(() => undefined);
}

/** Replace an entry's data directly — a mutation that answered with the new
 *  state saves a round trip. */
export function setQueryData<T>(key: QueryKey, update: T | ((prev: T | undefined) => T)): void {
  const e = entryFor(key);
  e.data =
    typeof update === "function" ? (update as (prev: T | undefined) => T)(e.data as T) : update;
  e.hasData = true;
  e.error = null;
  e.updatedAt = Date.now();
  e.lastSuccessAt = e.updatedAt;
  // A fetch already in flight would overwrite this with an older view.
  e.seq += 1;
  e.inFlight = null;
  publish(e);
}

/** Forget everything — on sign-out, and between tests. */
export function clearQueryCache(): void {
  for (const e of cache.values()) e.seq += 1;
  cache.clear();
}

export interface QueryOptions {
  /** Don't fetch (a signed-out page, a missing parameter). */
  enabled?: boolean;
  /** How long data counts as fresh, ms. A reader mounting on older data
   *  refetches behind it. Default 0: always revalidate on mount. */
  staleTime?: number;
  /** Refetch on a timer while the page is visible, ms. */
  refetchInterval?: number;
}

export interface QueryResult<T> extends QuerySnapshot<T> {
  /** Fetch again now, as the operator's own request. */
  refetch: () => Promise<void>;
}

/**
 * Read `key` through `fetcher`, sharing the result with every other reader
 * of the same key. `key: null` reads nothing (same as `enabled: false`).
 *
 * `fetcher` may change between renders (an inline closure); the newest one is
 * used. It is the *key* that identifies the data — two readers of one key
 * must fetch the same thing.
 */
export function useTrustTaskQuery<T>(
  key: QueryKey | null,
  fetcher: Fetcher<T>,
  options: QueryOptions = {},
): QueryResult<T> {
  const { enabled = true, staleTime = 0, refetchInterval } = options;
  const active = enabled && key !== null;

  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  // Looked up by the key's contents, so a new array literal each render
  // with the same contents is the same entry.
  const entry = key === null ? null : entryFor(key);
  if (entry) {
    entry.fetcher = (ctx) => fetcherRef.current(ctx);
  }

  const subscribe = useCallback(
    (listener: () => void) => {
      if (!entry) return () => {};
      entry.listeners.add(listener);
      return () => {
        entry.listeners.delete(listener);
      };
    },
    // `entry` is one object per key for as long as the cache holds it.
    [entry],
  );
  const snapshot = useSyncExternalStore(
    subscribe,
    () => (entry ? entry.snapshot : EMPTY),
    () => (entry ? entry.snapshot : EMPTY),
  ) as QuerySnapshot<T>;

  // Fetch on mount / key change when the entry is stale.
  useEffect(() => {
    if (!active || !entry) return;
    const fresh = entry.updatedAt > 0 && Date.now() - entry.updatedAt < staleTime;
    if (!fresh) void run(entry, { background: false });
  }, [entry, active, staleTime]);

  // Poll.
  useEffect(() => {
    if (!active || !entry || !refetchInterval) return;
    return startPolling(() => void run(entry, { background: true }), refetchInterval);
  }, [entry, active, refetchInterval]);

  const refetch = useCallback(
    () => (entry ? run(entry, { background: false }, true) : Promise.resolve()),
    [entry],
  );

  if (!active) {
    return { ...(EMPTY as QuerySnapshot<T>), refetch };
  }
  // Between the first render and the first fetch starting, nothing is in
  // flight yet; with no data and no error that is still "loading", not an
  // empty result.
  const loading = snapshot.loading || (!entry!.hasData && snapshot.error == null);
  return { ...snapshot, loading, refetch };
}

export interface MutationResult<A extends unknown[], R> {
  /** Run the mutation; on success the `invalidates` keys refetch. Rethrows. */
  mutate: (...args: A) => Promise<R>;
  busy: boolean;
  error: unknown;
  reset: () => void;
}

/**
 * Wrap a write so the reads it changes refresh after it succeeds.
 *
 * `invalidates` is awaited, so when `mutate` resolves the screen already shows
 * the new state.
 */
export function useTrustTaskMutation<A extends unknown[], R>(
  fn: (...args: A) => Promise<R>,
  options: { invalidates?: QueryKey[] } = {},
): MutationResult<A, R> {
  const [state, setState] = useState<{ busy: boolean; error: unknown }>({
    busy: false,
    error: null,
  });
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const invalidatesRef = useRef(options.invalidates);
  invalidatesRef.current = options.invalidates;

  const mutate = useCallback(async (...args: A) => {
    setState({ busy: true, error: null });
    try {
      const result = await fnRef.current(...args);
      const keys = invalidatesRef.current;
      if (keys && keys.length > 0) await invalidateQueries(...keys);
      setState({ busy: false, error: null });
      return result;
    } catch (e) {
      setState({ busy: false, error: e });
      throw e;
    }
  }, []);
  const reset = useCallback(() => setState({ busy: false, error: null }), []);
  return { mutate, busy: state.busy, error: state.error, reset };
}
