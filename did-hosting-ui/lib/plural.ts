/**
 * Counted nouns, chosen by `Intl.PluralRules` rather than `n === 1 ? "" : "s"`.
 *
 * The console's copy is English today, but routing every count through one
 * helper means a later string catalogue only has to supply the forms; the
 * category choice (`one`, `few`, `many`, …) is already the locale's.
 */

const rulesByLocale = new Map<string, Intl.PluralRules>();

function rules(locale?: string): Intl.PluralRules {
  const key = locale ?? "";
  let r = rulesByLocale.get(key);
  if (!r) {
    r = new Intl.PluralRules(locale);
    rulesByLocale.set(key, r);
  }
  return r;
}

/** The forms of a counted noun. `other` is required; the rest fall back to it. */
export interface PluralForms {
  one?: string;
  two?: string;
  few?: string;
  many?: string;
  zero?: string;
  other: string;
}

/** The form of the noun `forms` that goes with `count` (`"DID"` / `"DIDs"`). */
export function pluralForm(count: number, forms: PluralForms, locale?: string): string {
  const category = rules(locale).select(count) as keyof PluralForms;
  return forms[category] ?? forms.other;
}

/**
 * `count` and its noun: `plural(1, "DID", "DIDs")` is `"1 DID"`,
 * `plural(1200, "DID", "DIDs")` is `"1,200 DIDs"`.
 */
export function plural(count: number, one: string, other: string, locale?: string): string {
  return `${count.toLocaleString(locale)} ${pluralForm(count, { one, other }, locale)}`;
}
