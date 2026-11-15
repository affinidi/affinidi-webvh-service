/** DIDs: list, read, create, publish, transfer, roll back, delete. */

import type * as DidList from "../trust-tasks/did-management/did/list/0.2/payload";
import type * as DidInfo from "../trust-tasks/did-management/did/info/0.1/payload";
import type * as DidCheckName from "../trust-tasks/did-management/did/check-name/0.1/payload";
import type * as DidRegister from "../trust-tasks/did-management/did/register/0.1/payload";
import type * as DidDelete from "../trust-tasks/did-management/did/delete/0.1/payload";
import type * as DidChangeOwner from "../trust-tasks/did-management/did/change-owner/0.1/payload";
import type * as DidRollback from "../trust-tasks/did-management/did/rollback/0.1/payload";
import type * as DidSetState from "../trust-tasks/did-management/did/set-state/0.1/payload";
import type * as WitnessPublish from "../trust-tasks/webvh/witness/publish/0.1/payload";
import type * as AgentNameCheck from "../trust-tasks/did-management/agent-name/check/0.1/payload";
import type * as AgentNameResolve from "../trust-tasks/did-management/agent-name/resolve/0.1/payload";
import { ApiError } from "../http";
import { isRejection, trustTask } from "../trust-task";
import { WEBVH_EXT, didRecordFromWire, logEntriesFromWire, logMetadataFromEntries } from "../wire";
import { withStepUp } from "./auth";
import { DID_LIST_PAGE, T, didLog } from "./tasks";
import type {
  AgentNameAvailability,
  DidListPage,
  DidListQuery,
  AgentNameResolveResponse,
  CheckNameResponse,
  CreateDidResponse,
  DidDetailResponse,
  DidRecord,
  LogEntryInfo,
  OwnerChangeResult,
} from "./types";
import type { ReadOptions } from "./tasks";

export const didsApi = {
  // ---- DIDs ----

  /** One page of `did/list`, narrowed server-side. Pages are in mnemonic
   *  order; `nextCursor` is present while more may follow (a page can be
   *  short, even empty, and still have one). The cursor is bound to the
   *  filters: change one and start again without it. */
  listDidPage: async (q: DidListQuery = {}, opts: ReadOptions = {}): Promise<DidListPage> => {
    const webvh = {
      ...(q.search ? { search: q.search } : {}),
      ...(q.agentName ? { agentName: q.agentName } : {}),
    };
    const page = await trustTask<DidList.Payload, DidList.Response>(
      T.didList,
      {
        ...(q.owner ? { owner: q.owner } : {}),
        ...(q.domain ? { domain: q.domain } : {}),
        limit: q.limit ?? DID_LIST_PAGE,
        ...(q.cursor ? { cursor: q.cursor } : {}),
        ...(Object.keys(webvh).length > 0 ? { ext: { [WEBVH_EXT]: webvh } } : {}),
      },
      opts,
    );
    return {
      records: page.records.map(didRecordFromWire),
      ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
    };
  },

  /** Every slot the caller may see (an admin may name another `owner`),
   *  following `did/list`'s pages to the end. Only for a caller that truly
   *  needs all of them; a screen pages with `listDidPage`. */
  listDids: async (owner?: string): Promise<DidRecord[]> => {
    const out: DidRecord[] = [];
    for (let cursor: string | undefined; ;) {
      const page = await trustTask<DidList.Payload, DidList.Response>(T.didList, {
        ...(owner ? { owner } : {}),
        limit: DID_LIST_PAGE,
        ...(cursor ? { cursor } : {}),
      });
      out.push(...page.records.map(didRecordFromWire));
      // 0.2 pages by cursor: `nextCursor` is present while records remain.
      if (!page.nextCursor) return out;
      cursor = page.nextCursor;
    }
  },

  /** A slot with its log summarised: `did/info` for the record, `did/log` for
   *  the summary (webvh parameters are read from the log itself). */
  getDid: async (mnemonic: string, opts: ReadOptions = {}): Promise<DidDetailResponse> => {
    const [info, log] = await Promise.all([
      trustTask<DidInfo.Payload, DidInfo.Response>(T.didInfo, { mnemonic }, opts),
      didLog(mnemonic, false, opts).catch((e) => {
        // A slot with no published content has no log; that is not a failure.
        if (isRejection(e, "notFound")) return null;
        throw e;
      }),
    ]);
    // The entries are returned too, so a page showing the log does not
    // fetch `did/log` a second time.
    const entries = log ? logEntriesFromWire(log) : [];
    return {
      ...didRecordFromWire(info.record),
      log: log ? logMetadataFromEntries(entries) : null,
      entries,
    };
  },

  getDidLog: async (mnemonic: string, opts: ReadOptions = {}): Promise<LogEntryInfo[]> =>
    logEntriesFromWire(await didLog(mnemonic, false, opts)),

  /** The stored `did.jsonl`, verbatim. */
  getRawLog: async (mnemonic: string): Promise<string> =>
    (await didLog(mnemonic, true)).logContent ?? "",

  /** Claim a slot (`did/check-name` with `reserve: true`) — at `path`, or an
   *  auto-assigned one. Without `domain` the control plane uses the caller's
   *  default, then the system default. */
  createDid: async (path?: string, domain?: string): Promise<CreateDidResponse> => {
    const resp = await trustTask<DidCheckName.Payload, DidCheckName.Response>(T.didCheckName, {
      reserve: true,
      ...(path ? { path } : {}),
      ...(domain ? { domain } : {}),
    });
    if (!resp.reserved || !resp.record) {
      throw new ApiError(409, path ? `"${path}" is already taken` : "no slot could be reserved");
    }
    return { mnemonic: resp.record.mnemonic, didUrl: resp.record.didUrl ?? null };
  },

  /**
   * Move a DID to `newOwner`. An administrator's request moves it at once.
   * An owner's request only offers it: `offer` is set, the record is
   * unchanged, and the DID moves when the recipient accepts
   * (`acceptDidTransfer`). Naming the current owner withdraws an offer.
   */
  changeOwner: async (mnemonic: string, newOwner: string): Promise<OwnerChangeResult> => {
    const resp = await trustTask<DidChangeOwner.Payload, DidChangeOwner.Response>(
      T.didChangeOwner,
      { mnemonic, newOwner },
    );
    const host = (resp.ext as Record<string, unknown> | undefined)?.[WEBVH_EXT] as
      { ownerTransfer?: { status?: unknown; newOwner?: unknown; expiresAt?: unknown } } | undefined;
    const transfer = host?.ownerTransfer;
    return {
      record: didRecordFromWire(resp.record),
      offer:
        transfer?.status === "offered" && typeof transfer.newOwner === "string"
          ? { newOwner: transfer.newOwner, expiresAt: String(transfer.expiresAt ?? "") }
          : undefined,
    };
  },

  /** Accept a DID its owner offered to `me` (the signed-in DID): the same
   *  `did/change-owner`, sent by the recipient naming itself. */
  acceptDidTransfer: async (mnemonic: string, me: string): Promise<DidRecord> =>
    (await didsApi.changeOwner(mnemonic, me)).record,

  /** Is `path` free? A read-only probe. */
  checkName: async (path: string, domain?: string): Promise<CheckNameResponse> => {
    const resp = await trustTask<DidCheckName.Payload, DidCheckName.Response>(T.didCheckName, {
      path,
      ...(domain ? { domain } : {}),
    });
    return { available: resp.available };
  },

  /** Is an agent name (`/@name`) free to claim on `domain`? Binding itself is
   *  a signed did.jsonl publish through the user's agent. */
  checkAgentName: async (name: string, domain?: string): Promise<AgentNameAvailability> => {
    const r = await trustTask<AgentNameCheck.Payload, AgentNameCheck.Response>(T.agentNameCheck, {
      name,
      ...(domain ? { domain } : {}),
    });
    return { name: r.name, domain: r.domain, available: r.available, reserved: r.reserved };
  },

  /** DID -> its served agent names, batched. Only DIDs the caller may read
   *  and this service serves come back; read a miss and an empty list alike. */
  resolveAgentNames: async (
    dids: string[],
    opts: ReadOptions = {},
  ): Promise<AgentNameResolveResponse> => {
    if (dids.length === 0) return { names: {} };
    const r = await trustTask<AgentNameResolve.Payload, AgentNameResolve.Response>(
      T.agentNameResolve,
      { dids: dids as [string, ...string[]] },
      opts,
    );
    const names: Record<string, string[]> = {};
    for (const e of r.entries) names[e.did] = e.names;
    return { names };
  },

  /** Publish a signed `did.jsonl` to an existing slot (`did/register`). */
  uploadDid: async (mnemonic: string, log: string): Promise<void> => {
    await trustTask<DidRegister.Payload, DidRegister.Response>(T.didRegister, {
      path: mnemonic,
      method: "webvh",
      didData: log,
    });
  },

  /** Publish witness proofs (`did-witness.json`) for a slot. */
  uploadWitness: async (mnemonic: string, witnessJson: string): Promise<void> => {
    let witness: object;
    try {
      witness = JSON.parse(witnessJson);
    } catch (e) {
      throw new ApiError(400, `witness proofs are not valid JSON: ${(e as Error).message}`);
    }
    await trustTask<WitnessPublish.Payload, WitnessPublish.Response>(T.witnessPublish, {
      mnemonic,
      witness,
    });
  },

  /** Delete a DID slot. Needs a stepped-up session (`withStepUp`). */
  deleteDid: async (mnemonic: string): Promise<void> => {
    await withStepUp(() =>
      trustTask<DidDelete.Payload, DidDelete.Response>(T.didDelete, { mnemonic }),
    );
  },

  /**
   * Suspend a DID (resolvers get a deactivation marker; the log is kept) or
   * resume it. An administrator's suspension can only be lifted by an
   * administrator.
   */
  setDidState: async (mnemonic: string, state: "active" | "suspended"): Promise<DidRecord> => {
    const r = await trustTask<DidSetState.Payload, DidSetState.Response>(T.didSetState, {
      mnemonic,
      state,
    });
    return didRecordFromWire(r.record);
  },

  /** Discard the last log entry: roll back to `versionCount - 1`. */
  rollbackDid: async (mnemonic: string, versionCount: number): Promise<DidRecord> => {
    if (versionCount < 2) {
      throw new ApiError(400, "the first log entry cannot be rolled back");
    }
    const r = await trustTask<DidRollback.Payload, DidRollback.Response>(T.didRollback, {
      mnemonic,
      targetVersion: versionCount - 1,
    });
    return didRecordFromWire(r.record);
  },
};
