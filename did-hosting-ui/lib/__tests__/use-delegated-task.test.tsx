// @vitest-environment jsdom
/**
 * `useDelegatedTask`: the consent / re-submit state machine behind every
 * delegated edit on the DID detail screen.
 */

import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { LogEntryInfo } from "../api";
import {
  CONSENT_GRANTED_EVENT,
  useDelegatedTask,
  type UseDelegatedTaskOptions,
} from "../use-delegated-task";
import type { RequestTaskOutcome } from "../wallet";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

const CONSENT: RequestTaskOutcome = {
  kind: "consentRequired",
  payloadDigest: "z123456789",
} as RequestTaskOutcome;
const ACCEPTED = { kind: "accepted" } as RequestTaskOutcome;

const entry = (versionId: string): LogEntryInfo => ({
  versionId,
  versionTime: null,
  state: null,
  parameters: null,
});

function setup(over: Partial<UseDelegatedTaskOptions> = {}) {
  const notify = vi.fn();
  const onAccepted = vi.fn();
  const hook = renderHook((props: Partial<UseDelegatedTaskOptions>) =>
    useDelegatedTask({ latestVersionId: "1-a", notify, onAccepted, ...over, ...props }),
  );
  return { ...hook, notify, onAccepted };
}

describe("useDelegatedTask", () => {
  it("announces an accepted task and calls onAccepted", async () => {
    const { result, notify, onAccepted } = setup();
    let outcome: string | undefined;
    await act(async () => {
      outcome = await result.current.run(async () => ACCEPTED, vi.fn(), "Published.");
    });
    expect(outcome).toBe("accepted");
    expect(notify).toHaveBeenCalledWith("Done", "Published.");
    expect(onAccepted).toHaveBeenCalledTimes(1);
    expect(result.current.consent).toBeNull();
    expect(result.current.publishing).toBe(false);
  });

  it("pins the re-submit on consentRequired and replays it on the matching grant event", async () => {
    const { result } = setup();
    const resubmit = vi.fn(async () => "accepted" as const);
    await act(async () => {
      await result.current.run(async () => CONSENT, resubmit, "ok", undefined, "scidAlias");
    });
    expect(result.current.consent?.payloadDigest).toBe("z123456789");
    expect(result.current.consentOrigin).toBe("scidAlias");

    // A grant for some other task is ignored.
    act(() => {
      window.dispatchEvent(
        new CustomEvent(CONSENT_GRANTED_EVENT, { detail: { payloadDigest: "zother" } }),
      );
    });
    expect(resubmit).not.toHaveBeenCalled();

    act(() => {
      window.dispatchEvent(
        new CustomEvent(CONSENT_GRANTED_EVENT, { detail: { payloadDigest: "z123456789" } }),
      );
    });
    expect(resubmit).toHaveBeenCalledWith({ silent: true });
  });

  it("the manual button replays the pinned request", async () => {
    const { result } = setup();
    const resubmit = vi.fn(async () => "consent" as const);
    await act(async () => {
      await result.current.run(async () => CONSENT, resubmit, "ok");
    });
    act(() => result.current.resubmitNow());
    expect(resubmit).toHaveBeenCalledWith();
  });

  it("reports a failure with the orphan hint, but not when silent", async () => {
    const { result, notify } = setup();
    await act(async () => {
      await result.current.run(
        async () => {
          throw new Error("DID not found");
        },
        vi.fn(),
        "ok",
      );
    });
    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify.mock.calls[0]![0]).toBe("Error");
    expect(notify.mock.calls[0]![1]).toMatch(/^DID not found/);

    notify.mockClear();
    await act(async () => {
      await result.current.run(
        async () => {
          throw new Error("boom");
        },
        vi.fn(),
        "ok",
        { silent: true },
      );
    });
    expect(notify).not.toHaveBeenCalled();
  });

  it("retires the pending approval once the log moves past the pinned version", async () => {
    vi.useFakeTimers();
    let log = [entry("1-a")];
    const readLog = vi.fn(async () => log);
    const onMovedOn = vi.fn();
    const { result } = setup({ readLog, onMovedOn, pollIntervalMs: 1_000 });
    await act(async () => {
      await result.current.run(async () => CONSENT, vi.fn(), "ok");
    });
    // The first check: still at the pinned version.
    expect(readLog).toHaveBeenCalledTimes(1);
    expect(result.current.consent).not.toBeNull();

    log = [entry("1-a"), entry("2-b")];
    await act(async () => {
      vi.advanceTimersByTime(1_000);
    });
    expect(onMovedOn).toHaveBeenCalledWith(log);
    expect(result.current.consent).toBeNull();
  });

  it("does not watch the log with no approval outstanding", async () => {
    const readLog = vi.fn(async () => [entry("1-a")]);
    setup({ readLog });
    await act(async () => {});
    expect(readLog).not.toHaveBeenCalled();
  });
});
