/**
 * In-app confirmations and notices.
 *
 * The console used to confirm with `window.confirm` and report with
 * `window.alert`: blocking, title-less, always "OK / Cancel", and silently
 * suppressible by the browser ("prevent this page from creating additional
 * dialogs"), after which `confirm()` returns `false` without asking. This is
 * the replacement — a small store the `FeedbackHost` (mounted once, in the
 * root layout) renders:
 *
 * - `confirmAction` opens a dialog with a title, a body, an explicitly
 *   labelled action button and focus on Cancel. It can require the operator
 *   to type a name first (`typeToConfirm`) and can offer more than one action
 *   (`choices`). It resolves with the chosen value, or `null` on Cancel.
 * - `notify` shows a toast: success and info fade on their own, errors stay
 *   until dismissed.
 *
 * Callers never touch React context, so a handler deep inside a card can ask
 * without threading props.
 */

export type ToastKind = "success" | "error" | "info";

export interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  message?: string;
}

export interface ConfirmChoice {
  /** What `confirmAction` resolves with when this is chosen. */
  value: string;
  label: string;
  /** `danger` for an irreversible action. Default: `danger`. */
  variant?: "primary" | "secondary" | "danger";
  /** Only enabled once `typeToConfirm` has been typed. */
  requiresTyping?: boolean;
}

export interface ConfirmOptions {
  title: string;
  body: string;
  /** A list shown under the body — what exactly will be affected. */
  details?: string[];
  /** The action button's label (single-action dialogs). Default "Confirm". */
  confirmLabel?: string;
  cancelLabel?: string;
  /** Style the action as destructive. Default true. */
  destructive?: boolean;
  /** Text the operator must type before a destructive action is enabled. */
  typeToConfirm?: string;
  /** Several actions in place of the single `confirmLabel` one. */
  choices?: ConfirmChoice[];
}

export interface PendingConfirm extends ConfirmOptions {
  id: number;
  resolve: (value: string | null) => void;
}

export interface FeedbackState {
  toasts: Toast[];
  confirm: PendingConfirm | null;
}

/** The value a single-action dialog resolves with. */
export const CONFIRMED = "confirm";

/** How long a non-error toast stays, ms. */
export const TOAST_MS = 6000;

let state: FeedbackState = { toasts: [], confirm: null };
const queue: PendingConfirm[] = [];
const listeners = new Set<() => void>();
let nextId = 1;

function emit(next: FeedbackState): void {
  state = next;
  for (const l of [...listeners]) l();
}

export function subscribeFeedback(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function getFeedbackState(): FeedbackState {
  return state;
}

/**
 * Ask before doing something. Resolves with the chosen action's `value`
 * (`CONFIRMED` for a single-action dialog), or `null` when cancelled.
 * Requests made while a dialog is open wait their turn.
 */
export function confirmAction(options: ConfirmOptions): Promise<string | null> {
  return new Promise((resolve) => {
    const pending: PendingConfirm = { ...options, id: nextId++, resolve };
    if (state.confirm) queue.push(pending);
    else emit({ ...state, confirm: pending });
  });
}

/** `confirmAction` for the common yes/no case. */
export async function confirm(options: ConfirmOptions): Promise<boolean> {
  return (await confirmAction(options)) !== null;
}

/** Settle the open dialog (the host calls this). */
export function settleConfirm(id: number, value: string | null): void {
  const open = state.confirm;
  if (!open || open.id !== id) return;
  open.resolve(value);
  emit({ ...state, confirm: queue.shift() ?? null });
}

/** Show a toast. Returns its id. */
export function notify(kind: ToastKind, title: string, message?: string): number {
  const id = nextId++;
  emit({ ...state, toasts: [...state.toasts, { id, kind, title, message }] });
  return id;
}

export function dismissToast(id: number): void {
  if (!state.toasts.some((t) => t.id === id)) return;
  emit({ ...state, toasts: state.toasts.filter((t) => t.id !== id) });
}

/**
 * The `(title, message)` notifier the DID cards and the delegated-edit hook
 * take. Their titles are "Error", "Success", "Done" or a short heading, so the
 * kind is read off the title.
 */
export function showMessage(title: string, message: string): void {
  const kind: ToastKind = /error|fail|could not/i.test(title)
    ? "error"
    : /^(success|done)$/i.test(title)
      ? "success"
      : "info";
  notify(kind, title, message);
}

/** Forget everything — between tests. */
export function resetFeedbackForTests(): void {
  for (const p of queue.splice(0)) p.resolve(null);
  state.confirm?.resolve(null);
  state = { toasts: [], confirm: null };
  for (const l of [...listeners]) l();
}
