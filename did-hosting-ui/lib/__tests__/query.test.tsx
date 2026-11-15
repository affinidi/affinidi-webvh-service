// @vitest-environment jsdom
/**
 * `useTrustTaskQuery`: dedup, stale-while-revalidate, the stale-response
 * guard, invalidation, and visibility-aware polling.
 */

import { act, cleanup, render, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  clearQueryCache,
  invalidateQueries,
  setQueryData,
  useTrustTaskMutation,
  useTrustTaskQuery,
  type FetchContext,
} from "../query";

beforeEach(() => {
  clearQueryCache();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

/** A promise and its resolver. */
function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

describe("useTrustTaskQuery", () => {
  it("dedups readers of one key onto one request", async () => {
    const fetcher = vi.fn(async () => "config");
    function Reader() {
      const q = useTrustTaskQuery(["server", "config"], fetcher);
      return <span>{q.data ?? "…"}</span>;
    }
    const { findAllByText } = render(
      <>
        <Reader />
        <Reader />
        <Reader />
      </>,
    );
    expect(await findAllByText("config")).toHaveLength(3);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("is loading before the first answer, not empty", () => {
    const { result } = renderHook(() => useTrustTaskQuery(["k"], () => new Promise(() => {})));
    expect(result.current.loading).toBe(true);
    expect(result.current.data).toBeUndefined();
  });

  it("shows held data at once and revalidates behind it", async () => {
    setQueryData(["dids"], ["old"]);
    const next = deferred<string[]>();
    const { result } = renderHook(() => useTrustTaskQuery(["dids"], () => next.promise));
    expect(result.current.data).toEqual(["old"]);
    expect(result.current.loading).toBe(false);
    expect(result.current.refreshing).toBe(true);
    await act(async () => next.resolve(["new"]));
    expect(result.current.data).toEqual(["new"]);
  });

  it("skips the revalidation while data is fresh", async () => {
    setQueryData(["fresh"], 1);
    const fetcher = vi.fn(async () => 2);
    const { result } = renderHook(() =>
      useTrustTaskQuery(["fresh"], fetcher, { staleTime: 60_000 }),
    );
    expect(result.current.data).toBe(1);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("never shows a late answer for a key the reader has moved off", async () => {
    const answers: Record<string, ReturnType<typeof deferred<string>>> = {
      "1h": deferred<string>(),
      "24h": deferred<string>(),
    };
    const { result, rerender } = renderHook(
      ({ range }: { range: string }) =>
        useTrustTaskQuery(["timeseries", range], () => answers[range]!.promise),
      { initialProps: { range: "1h" } },
    );
    rerender({ range: "24h" });
    await act(async () => answers["24h"]!.resolve("day"));
    await act(async () => answers["1h"]!.resolve("hour"));
    expect(result.current.data).toBe("day");
  });

  it("drops an older fetch's answer when a newer fetch of the same key wins", async () => {
    const first = deferred<string>();
    const second = deferred<string>();
    const fetcher = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const { result } = renderHook(() => useTrustTaskQuery(["x"], fetcher));
    await act(async () => {
      void result.current.refetch();
    });
    await act(async () => second.resolve("new"));
    await act(async () => first.resolve("old"));
    expect(result.current.data).toBe("new");
  });

  it("keeps the last good data beside an error", async () => {
    setQueryData(["y"], "good");
    const { result } = renderHook(() =>
      useTrustTaskQuery(["y"], async () => {
        throw new Error("boom");
      }),
    );
    await waitFor(() => expect(result.current.error).toBeInstanceOf(Error));
    expect(result.current.data).toBe("good");
  });

  it("reads nothing while disabled", () => {
    const fetcher = vi.fn(async () => 1);
    const { result } = renderHook(() => useTrustTaskQuery(["z"], fetcher, { enabled: false }));
    expect(fetcher).not.toHaveBeenCalled();
    expect(result.current.loading).toBe(false);
  });

  it("refetches what a mutation invalidates, by prefix", async () => {
    let n = 0;
    const { result } = renderHook(() => useTrustTaskQuery(["acl", "list"], async () => ++n));
    await waitFor(() => expect(result.current.data).toBe(1));
    await act(async () => {
      await invalidateQueries(["acl"]);
    });
    expect(result.current.data).toBe(2);
  });

  it("polls as a background request, and not while the page is hidden", async () => {
    vi.useFakeTimers();
    let hidden = false;
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => (hidden ? "hidden" : "visible"),
    });
    const calls: FetchContext[] = [];
    renderHook(() =>
      useTrustTaskQuery(
        ["overview"],
        async (ctx) => {
          calls.push(ctx);
          return calls.length;
        },
        { refetchInterval: 5_000 },
      ),
    );
    await act(async () => {});
    expect(calls).toEqual([{ background: false }]);
    await act(async () => {
      vi.advanceTimersByTime(5_000);
    });
    expect(calls.at(-1)).toEqual({ background: true });
    const before = calls.length;
    hidden = true;
    await act(async () => {
      vi.advanceTimersByTime(15_000);
    });
    expect(calls.length).toBe(before);
  });
});

describe("useTrustTaskMutation", () => {
  it("invalidates its keys after success, and reports failure", async () => {
    let n = 0;
    const read = renderHook(() => useTrustTaskQuery(["domains"], async () => ++n));
    await waitFor(() => expect(read.result.current.data).toBe(1));

    const write = renderHook(() =>
      useTrustTaskMutation(
        async (fail: boolean) => {
          if (fail) throw new Error("nope");
          return "ok";
        },
        { invalidates: [["domains"]] },
      ),
    );
    await act(async () => {
      await write.result.current.mutate(false);
    });
    expect(read.result.current.data).toBe(2);

    await act(async () => {
      await write.result.current.mutate(true).catch(() => {});
    });
    expect(write.result.current.error).toBeInstanceOf(Error);
    expect(read.result.current.data).toBe(2);
  });
});
