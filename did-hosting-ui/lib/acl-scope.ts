/**
 * The ACL "Add Entry" / row-editor's domain-scope draft — the form's view
 * of an `AclEntry`'s `DomainScope` — and the pure logic around it. Split
 * out of `app/acl/index.tsx` so it is testable without rendering the
 * screen (`app/*` pulls in `react-native`).
 */

import type { AclEntry, DomainScope } from "./api";

export type ScopeKind = "all" | "allowed" | "allowed_with_default";

export interface ScopeDraft {
  kind: ScopeKind;
  domains: string[];
  /** Only meaningful when `kind === "allowed_with_default"`. */
  default: string;
}

/** Scope draft for an Admin/Service "Add Entry" grant, and the shape the
 * "Add Entry" form's Owner default falls back to while no system default
 * domain is configured yet. Role-based access already constrains an
 * Admin/Service's surface, so "All domains" is fine as their default; a
 * fresh Owner instead gets the system default domain — see
 * `defaultScopeForRole`, which computes that scope because `acl/grant` no
 * longer infers one server-side. */
export const DEFAULT_SCOPE_DRAFT: ScopeDraft = {
  kind: "all",
  domains: [],
  default: "",
};

export function aclEntryToDraft(entry: AclEntry): ScopeDraft {
  if (!entry.domains || entry.domains.kind === "all") {
    return { kind: "all", domains: [], default: "" };
  }
  if (entry.domains.kind === "allowed") {
    return { kind: "allowed", domains: [...entry.domains.domains], default: "" };
  }
  return {
    kind: "allowed_with_default",
    domains: [...entry.domains.domains],
    default: entry.domains.default,
  };
}

/** Convert the draft back to wire shape. Returns `undefined` when the
 * draft is unset/invalid so the caller can omit the field. */
export function draftToScope(draft: ScopeDraft): DomainScope | undefined {
  if (draft.kind === "all") return { kind: "all" };
  if (draft.kind === "allowed") {
    if (draft.domains.length === 0) return undefined;
    return { kind: "allowed", domains: draft.domains };
  }
  if (draft.domains.length === 0 || !draft.default) return undefined;
  return {
    kind: "allowed_with_default",
    domains: draft.domains,
    default: draft.default,
  };
}

/**
 * The scope a fresh "Add Entry" grant gets before the operator has touched
 * the scope editor.
 *
 * A new Owner is scoped to the system default domain
 * (`AllowedWithDefault([defaultDomain], defaultDomain)`) — restrictive by
 * default, matching the removed REST route's `POST /api/acl`, which applied
 * the same default server-side. `acl/grant`'s scopes are explicit on the
 * wire and the maintainer no longer infers one, so the console computes
 * and sends it instead. Admin and Service default to "All domains" —
 * role-based access already constrains their surface — and so does an
 * Owner grant while no system default domain is configured yet (a fresh
 * deployment with no domains seeded), the same fallback the removed route
 * took.
 */
export function defaultScopeForRole(
  role: "admin" | "owner" | "service",
  defaultDomain: string | null,
): ScopeDraft {
  if (role === "owner" && defaultDomain) {
    return { kind: "allowed_with_default", domains: [defaultDomain], default: defaultDomain };
  }
  return DEFAULT_SCOPE_DRAFT;
}

/** Validation hook used by the Save / Add buttons — returns an error
 * message when the draft is not submittable. */
export function validateScopeDraft(draft: ScopeDraft): string | null {
  if (draft.kind === "all") return null;
  if (draft.domains.length === 0) return "Select at least one domain";
  if (draft.kind === "allowed_with_default" && !draft.default) {
    return "Pick a default domain";
  }
  if (
    draft.kind === "allowed_with_default" &&
    !draft.domains.includes(draft.default)
  ) {
    return "Default must be one of the selected domains";
  }
  return null;
}
