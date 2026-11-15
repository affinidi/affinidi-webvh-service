/**
 * The console's client for its control plane.
 *
 * Every management call is a signed Trust Task through `POST /api/trust-tasks`
 * (see `trust-task.ts` for the binding and how replies are checked). The
 * request and response shapes are the generated types in `lib/trust-tasks/`
 * (`npm run gen:tasks`, from the versions `did-hosting-common/trust-tasks.lock`
 * pins); `wire.ts` projects each reply into the view models
 * below, which are what the screens render.
 *
 * One thing stays plain HTTP: the unauthenticated `/api/health` liveness
 * probe. Session renewal (`auth/refresh`, in `session.ts`), passkey enrolment
 * and login are Trust Tasks too; only the browser's WebAuthn ceremony is not, and
 * its data rides inside their payloads.
 *
 * The calls live in per-family modules under `api/` (`dids`, `acl`,
 * `domains`, `auth`, `service`); this module joins them into the one
 * `api` object the screens use, and re-exports the view models.
 */

import { aclApi } from "./api/acl";
import { authApi } from "./api/auth";
import { didsApi } from "./api/dids";
import { domainsApi } from "./api/domains";
import { serviceApi } from "./api/service";

export { ApiError } from "./http";
export * from "./session";
export {
  TrustTaskRejection,
  checkReply,
  isRejection,
  resetServiceInfo,
  retryDelayMs,
} from "./trust-task";
export type { Response as ServerInfo } from "./trust-tasks/did-management/server/info/0.1/payload";
export * from "./api/types";
export { T } from "./task-types";
export type { ReadOptions } from "./api/tasks";
export { needsStepUp } from "./api/auth";
export { looksLikeAgentName, splitAgentName } from "./api/acl";

export const api = {
  ...serviceApi,
  ...didsApi,
  ...aclApi,
  ...domainsApi,
  ...authApi,
};
