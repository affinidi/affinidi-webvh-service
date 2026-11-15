/**
 * The access-control list. The webvh-specific members travel under
 * `ext["vnd.affinidi.webvh"]`.
 */

import type * as AclList from "../trust-tasks/acl/list/0.3/payload";
import type * as AclShow from "../trust-tasks/acl/show/0.2/payload";
import type * as AclGrant from "../trust-tasks/acl/grant/0.2/payload";
import type * as AclRevoke from "../trust-tasks/acl/revoke/0.2/payload";
import type * as AclChangeRole from "../trust-tasks/acl/change-role/0.2/payload";
import { ApiError } from "../http";
import { trustTask } from "../trust-task";
import { WEBVH_EXT, aclEntryFromWire, actNarrowing, actOf, defaultDomainOf } from "../wire";
import { didsApi } from "./dids";
import { withStepUp } from "./auth";
import { T } from "./tasks";
import type { AclEntry, AclListResponse, DidRecord, DomainScope, Role } from "./types";

/**
 * The AclEntry 0.2 a grant states for `subject`. Everything is explicit:
 * the entry's domains are its `act` scope (always `all` for Admin and
 * Service), `keys` is `none` and `capabilities` the role's `ceiling` — the
 * only values this control plane holds — and there is no `approve`. The
 * webvh `ext` carries only `quota` and the `defaultDomain`, which must be
 * one of the act contexts.
 */
function aclGrantEntry(
  subject: string,
  role: Role,
  domains: DomainScope,
  label: string | null | undefined,
  maxTotalSize: number | null | undefined,
  maxDidCount: number | null | undefined,
): AclGrant.AclEntry {
  const act = actOf(role, domains);
  const defaultDomain = act.scope === "contexts" ? defaultDomainOf(domains) : undefined;
  const webvh: Record<string, unknown> = {};
  const quota: Record<string, number> = {};
  if (typeof maxTotalSize === "number") quota.maxTotalSize = maxTotalSize;
  if (typeof maxDidCount === "number") quota.maxDidCount = maxDidCount;
  if (Object.keys(quota).length > 0) webvh.quota = quota;
  if (defaultDomain !== undefined) webvh.defaultDomain = defaultDomain;
  return {
    subject,
    role,
    act,
    keys: { scope: "none" },
    capabilities: { scope: "ceiling" },
    ...(label !== null && label !== undefined ? { label } : {}),
    ...(Object.keys(webvh).length > 0 ? { ext: { [WEBVH_EXT]: webvh } } : {}),
  };
}

// ---------------------------------------------------------------------------
// ACL subject resolution — an agent name typed where an ACL takes a DID
// ---------------------------------------------------------------------------
//
// `acl/grant` stores whatever `subject` it is given verbatim — the control
// plane resolves nothing (unlike the removed REST `POST /api/acl`, which
// resolved a name to a DID server-side via `resolve_did_or_agent_name`
// before it ever reached storage). A subject typed as a name the console
// doesn't resolve first would silently create an entry keyed on a string
// nothing can ever authenticate as.

/** Cheap syntactic test — the `/@` marker — mirroring
 *  `agent_names::AgentName::looks_like_agent_name` (Rust) used server-side
 *  for the same purpose. No network access; just decides whether `input`
 *  is an agent name shape before doing any resolution work. */
export function looksLikeAgentName(input: string): boolean {
  return input.includes("/@");
}

/** Split an agent name (`example.com/@alice`, with or without a leading
 *  `https://`, and tolerant of trailing context path segments or a
 *  trailing slash) into its hosting domain and bare local name. `null`
 *  when the `/@` marker is present but the surrounding shape isn't one
 *  this parser understands — an empty domain, the community name
 *  (`example.com/@`, which no ACL role can be granted to), or a second
 *  `/@` marker. Domain is lower-cased; the local name keeps its case. */
export function splitAgentName(input: string): { domain: string; name: string } | null {
  const noScheme = input.trim().replace(/^https?:\/\//i, "");
  const idx = noScheme.indexOf("/@");
  if (idx < 1) return null;
  const domain = noScheme.slice(0, idx).toLowerCase();
  const afterMarker = noScheme.slice(idx + 2).replace(/\/+$/, "");
  const nextSlash = afterMarker.indexOf("/");
  const name = nextSlash === -1 ? afterMarker : afterMarker.slice(0, nextSlash);
  if (!domain || !name || name.includes("/@")) return null;
  return { domain, name };
}

export const aclApi = {
  // ---- ACL ----
  //
  // The webvh-specific members travel under `ext["vnd.affinidi.webvh"]`.

  listAcl: async (): Promise<AclListResponse> => {
    // 0.3 pages by cursor: `nextCursor` is present while entries remain.
    const entries: AclEntry[] = [];
    for (let cursor: string | undefined; ;) {
      const resp = await trustTask<AclList.Payload, AclList.Response>(
        T.aclList,
        cursor ? { cursor } : {},
      );
      entries.push(...resp.entries.map(aclEntryFromWire));
      if (!resp.nextCursor) return { entries };
      cursor = resp.nextCursor;
    }
  },

  /**
   * Turn what an operator typed into the ACL "Add Entry" field into a
   * DID. A DID is returned verbatim — `acl/grant` stores whatever
   * `subject` it is given, so this is the only place a name gets resolved
   * before it lands there.
   *
   * An agent name is resolved once, here: every DID this deployment hosts
   * is searched for one whose registry currently serves the name, and
   * `agent-name/resolve` — the same task an owner's console calls to show
   * a DID's addresses — confirms the binding is still live (enabled, and
   * claimed by the DID's current document) before it is accepted. The ACL
   * entry is then created against the DID, never the name: the name can
   * be released and re-claimed by someone else later, and that must not
   * silently move the grant (mirrors the removed REST route's
   * `resolve_did_or_agent_name`, which resolved once at write time for
   * the same reason).
   *
   * Throws when the input looks like an agent name but does not resolve
   * to a DID hosted here. Anything that doesn't look like an agent name
   * (including a malformed DID) is passed through unchanged — `acl/grant`
   * is left to refuse it in whatever shape it likes.
   */
  resolveAclSubject: async (input: string): Promise<string> => {
    const trimmed = input.trim();
    if (!looksLikeAgentName(trimmed)) return trimmed;
    const parsed = splitAgentName(trimmed);
    if (!parsed) {
      throw new ApiError(400, `'${trimmed}' is not a valid agent name`);
    }
    const served = `${parsed.domain}/@${parsed.name}`;
    // The one slot holding the name, from the name index — not every DID.
    const { records: dids } = await didsApi.listDidPage({
      domain: parsed.domain,
      agentName: parsed.name,
      limit: 1,
    });
    const hasDidId = (d: DidRecord): d is DidRecord & { didId: string } => d.didId !== null;
    const candidates = dids.filter(
      (d): d is DidRecord & { didId: string } =>
        hasDidId(d) &&
        d.domain === parsed.domain &&
        (d.agentNames ?? []).some((e) => e.enabled && e.name === parsed.name),
    );
    if (candidates.length > 0) {
      const { names } = await didsApi.resolveAgentNames(candidates.map((d) => d.didId));
      const match = candidates.find((d) => names[d.didId]?.includes(served));
      if (match) return match.didId;
    }
    throw new ApiError(
      404,
      `agent name '${trimmed}' does not resolve to a DID hosted here — bind it first, or use the DID directly`,
    );
  },

  /**
   * `acl/grant`. `subject` is a DID, or an agent name hosted here
   * (`example.com/@alice`) — resolved to the DID it currently serves
   * before the grant is sent; see `resolveAclSubject`. `acl/grant`'s
   * scopes are explicit on the wire and the maintainer no longer infers
   * one (the removed REST route did, for a domain-less Owner) — a caller
   * granting Owner access is expected to pass `opts.domains` itself
   * (`Add Entry`'s default-domain-scope logic is what fills it in when
   * the operator hasn't chosen one). Omitting it falls back to `all`
   * here, matching the unrestricted default a bare Admin/Service grant
   * already gets.
   */
  createAcl: async (
    subject: string,
    role: Role,
    opts?: {
      label?: string;
      maxTotalSize?: number;
      maxDidCount?: number;
      domains?: DomainScope;
    },
  ): Promise<AclEntry> => {
    const did = await aclApi.resolveAclSubject(subject);
    // Granting an admin or service entry needs a stepped-up session.
    const resp = await withStepUp(() =>
      trustTask<AclGrant.Payload, AclGrant.Response>(T.aclGrant, {
        entry: aclGrantEntry(
          did,
          role,
          opts?.domains ?? { kind: "all" },
          opts?.label,
          opts?.maxTotalSize,
          opts?.maxDidCount,
        ),
      }),
    );
    return aclEntryFromWire(resp.entry);
  },

  /**
   * Change an entry, sending only what differs from it.
   *
   * `loaded` is the entry as the screen loaded it. When given, the update is
   * diffed against it and nothing is read first: an unchanged entry costs no
   * round trip, a label edit is one `acl/grant`, a role change alone is one
   * `acl/change-role`. Without it the entry is read with `acl/show` first.
   * A stale `loaded` cannot clobber a concurrent role change — `change-role`
   * is state-checked against `fromRole` and refused on a mismatch.
   *
   * A role change is `acl/change-role`. Anything else re-emits `acl/grant`,
   * which may re-assert or widen an entry but never narrow it: dropping
   * domains is first an `acl/revoke` narrowing of the act scope to the
   * domains kept, then the grant states the rest. A combined update sends the
   * role change first. These are separate tasks, not a transaction: if a
   * later one fails, the earlier ones have applied, and the error says which
   * step failed so the screen can reload the entry.
   */
  updateAcl: async (
    did: string,
    updates: {
      role?: Role;
      label?: string | null;
      maxTotalSize?: number | null;
      maxDidCount?: number | null;
      domains?: DomainScope;
    },
    loaded?: AclEntry,
  ): Promise<AclEntry> => {
    const notFound = () => new ApiError(404, `subject ${did} not found in ACL`);
    const partly = (step: string, e: unknown): never => {
      if (e instanceof ApiError) {
        e.message = `${e.message} (${step} failed after the role change was applied — reload to see the entry as it is now)`;
      }
      throw e;
    };

    let entry = loaded ?? (await aclApi.aclShow(did));
    if (!entry) throw notFound();
    let roleChanged = false;

    if (updates.role !== undefined && updates.role !== entry.role) {
      // A move to admin or service needs a stepped-up session.
      const fromRole = entry.role;
      const toRole = updates.role;
      const resp = await withStepUp(() =>
        trustTask<AclChangeRole.Payload, AclChangeRole.Response>(T.aclChangeRole, {
          subject: did,
          fromRole,
          toRole,
        }),
      );
      entry = aclEntryFromWire(resp.entry);
      roleChanged = true;
    }

    const base = entry;
    const domains = updates.domains ?? base.domains ?? { kind: "all" };
    const label = updates.label === undefined ? base.label : updates.label;
    const maxTotalSize =
      updates.maxTotalSize === undefined ? base.max_total_size : updates.maxTotalSize;
    const maxDidCount =
      updates.maxDidCount === undefined ? base.max_did_count : updates.maxDidCount;
    // The grant this entry already states, and the one the update asks for.
    // Equal means there is nothing to send.
    const held = aclGrantEntry(
      did,
      base.role,
      base.domains ?? { kind: "all" },
      base.label,
      base.max_total_size,
      base.max_did_count,
    );
    const wanted = aclGrantEntry(did, base.role, domains, label, maxTotalSize, maxDidCount);
    if (JSON.stringify(held) === JSON.stringify(wanted)) return base;

    try {
      let granted = base;
      const narrower = actNarrowing(
        actOf(base.role, base.domains ?? { kind: "all" }),
        actOf(base.role, domains),
      );
      if (narrower) {
        const revoked = await trustTask<AclRevoke.Payload, AclRevoke.Response>(T.aclRevoke, {
          subject: did,
          revocation: { kind: "act", act: narrower },
        });
        if (!revoked.entry) throw notFound();
        granted = aclEntryFromWire(revoked.entry);
      }
      const grantRole = granted.role;
      // Re-asserting an admin or service entry needs a stepped-up session.
      const resp = await withStepUp(() =>
        trustTask<AclGrant.Payload, AclGrant.Response>(T.aclGrant, {
          entry: aclGrantEntry(did, grantRole, domains, label, maxTotalSize, maxDidCount),
        }),
      );
      return aclEntryFromWire(resp.entry);
    } catch (e) {
      if (roleChanged) partly("updating the entry", e);
      throw e;
    }
  },

  /** Single-entry lookup. `null` when the subject is not in the ACL. */
  aclShow: async (did: string): Promise<AclEntry | null> => {
    const resp = await trustTask<AclShow.Payload, AclShow.Response>(T.aclShow, { subject: did });
    return resp.entry ? aclEntryFromWire(resp.entry) : null;
  },

  deleteAcl: async (did: string): Promise<void> => {
    await trustTask<AclRevoke.Payload, AclRevoke.Response>(T.aclRevoke, {
      subject: did,
      revocation: { kind: "entry" },
    });
  },
};
