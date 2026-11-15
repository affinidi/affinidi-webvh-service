/**
 * The message to show for a caught value.
 *
 * Every `catch` in the console catches `unknown` — a rejection can be an
 * `Error`, an `ApiError`, a string a library threw, or anything else — and
 * reads its text through this, so a screen never reaches for `err.message` on
 * a value that may not have one.
 */
export function errorMessage(e: unknown, fallback = "Something went wrong."): string {
  if (e instanceof Error && e.message) return e.message;
  if (typeof e === "string" && e) return e;
  return fallback;
}
