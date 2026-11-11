/**
 * Timer-driven refreshes for pages that keep themselves current.
 *
 * A poll is not the operator doing anything, so every tick is sent as a
 * background request (`BACKGROUND_REQUEST_HEADER` in `http.ts`): the control
 * plane serves it but does not count it as activity, and a console left open
 * on a polling page still signs out after the configured idle timeout.
 *
 * Ticks are also skipped while the page is hidden (a background tab, a
 * minimised window): nobody is looking at what they would refresh. When the
 * page becomes visible again it refreshes once straight away, still as a
 * background request, since becoming visible is not proof that anyone is
 * there.
 */

/** What a tick is told about itself. Always `background: true`; passed so a
 *  tick can hand it straight to an `api` read. */
export interface PollTick {
  background: true;
}

/** The parts of the browser a poll reads. Injectable for tests. */
export interface PollEnvironment {
  isHidden(): boolean;
  onVisibilityChange(listener: () => void): () => void;
  setInterval(fn: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
}

function browserEnvironment(): PollEnvironment {
  const doc = typeof document !== "undefined" ? document : undefined;
  return {
    isHidden: () => doc?.visibilityState === "hidden",
    onVisibilityChange: (listener) => {
      if (!doc) return () => {};
      doc.addEventListener("visibilitychange", listener);
      return () => doc.removeEventListener("visibilitychange", listener);
    },
    setInterval: (fn, ms) => setInterval(fn, ms),
    clearInterval: (handle) => clearInterval(handle as ReturnType<typeof setInterval>),
  };
}

/**
 * Call `tick` every `intervalMs` while the page is visible, as a background
 * request. Does not call it immediately: the page's first load is the
 * operator's own navigation and is sent as an ordinary request by the caller.
 *
 * @returns a function that stops the poll.
 */
export function startPolling(
  tick: (t: PollTick) => void,
  intervalMs: number,
  env: PollEnvironment = browserEnvironment(),
): () => void {
  const fire = () => {
    if (!env.isHidden()) tick({ background: true });
  };
  const handle = env.setInterval(fire, intervalMs);
  const stopListening = env.onVisibilityChange(fire);
  return () => {
    env.clearInterval(handle);
    stopListening();
  };
}
