/**
 * ARIA attributes React Native's types do not list but `react-native-web`
 * renders (`aria-level`, `aria-pressed`, `aria-describedby`, `aria-sort`,
 * `aria-invalid`, `aria-required`, `aria-current`).
 *
 * Spread the result onto a `View`, `Text`, `Pressable` or `TextInput`:
 * `<Text role="heading" {...webAria({ level: 1 })}>`. Native ignores them;
 * the shared primitives in `components/` already set the ones they need.
 */
export interface WebAria {
  level?: number;
  pressed?: boolean;
  describedBy?: string;
  sort?: "ascending" | "descending" | "none";
  invalid?: boolean;
  required?: boolean;
  current?: "page" | "step" | "true" | boolean;
}

export function webAria(attrs: WebAria): Record<string, never> {
  const out: Record<string, unknown> = {};
  if (attrs.level !== undefined) out["aria-level"] = attrs.level;
  if (attrs.pressed !== undefined) out["aria-pressed"] = attrs.pressed;
  if (attrs.describedBy !== undefined) out["aria-describedby"] = attrs.describedBy;
  if (attrs.sort !== undefined) out["aria-sort"] = attrs.sort;
  if (attrs.invalid !== undefined) out["aria-invalid"] = attrs.invalid;
  if (attrs.required !== undefined) out["aria-required"] = attrs.required;
  if (attrs.current !== undefined) out["aria-current"] = attrs.current;
  // Typed as an empty record so it spreads onto any React Native props
  // without widening them; the values are only read by react-native-web.
  return out as Record<string, never>;
}
