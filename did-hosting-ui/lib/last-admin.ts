/**
 * The one rule the console checks before removing an ACL entry: the control
 * plane never lets its last administrator go (`acl/revoke` answers
 * `lastAuthorityProtected`). The server is the guard; the console checks
 * first only so it never deletes an administrator's DIDs and then has the
 * removal they were deleted for refused.
 */

import type { AclEntry } from "./api";

/** Whether `did` is the only `admin` entry in `entries`. */
export function isLastAdmin(entries: readonly AclEntry[], did: string): boolean {
  const admins = entries.filter((e) => e.role === "admin");
  return admins.length === 1 && admins[0]!.did === did;
}
