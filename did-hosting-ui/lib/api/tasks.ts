/**
 * The small helpers more than one `api/*` family shares. The Trust Task type
 * URIs live in `../task-types.ts` (re-exported here as `T`).
 */

import type * as DidLog from "../trust-tasks/did-management/did/log/0.1/payload";
import { T } from "../task-types";
import { trustTask } from "../trust-task";

export { T };

/** Largest page `did/list` answers. */
export const DID_LIST_PAGE = 1000;

/** Options for a read a page may also send on a timer. `background` marks a
 *  call the operator did not make, so it does not keep the session alive. */
export interface ReadOptions {
  background?: boolean;
}

/** The control plane's `did/log` for `mnemonic`. */
export function didLog(
  mnemonic: string,
  raw: boolean,
  opts: ReadOptions = {},
): Promise<DidLog.Response> {
  return trustTask<DidLog.Payload, DidLog.Response>(
    T.didLog,
    {
      mnemonic,
      ...(raw ? { raw: true } : {}),
    },
    opts,
  );
}
