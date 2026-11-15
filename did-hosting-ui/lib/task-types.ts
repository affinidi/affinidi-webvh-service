/**
 * The Type URI of every Trust Task the console sends.
 *
 * Each is typed as its generated `TYPE_URI`, so a typo or a version the lock
 * does not pin fails the typecheck, and a `trust-tasks add` that moves a task
 * moves it here or fails to build. Only the types are imported — the
 * generated modules carry their schemas as values, which the bundle does not
 * need.
 *
 * A module of its own, rather than part of `api.ts` (which re-exports it), so
 * `trust-task.ts` — which `api.ts` imports — can build its retry-safe set from
 * the same table without an import cycle.
 */

import type * as DidList from "./trust-tasks/did-management/did/list/0.2/payload";
import type * as DidInfo from "./trust-tasks/did-management/did/info/0.1/payload";
import type * as DidLog from "./trust-tasks/did-management/did/log/0.1/payload";
import type * as DidCheckName from "./trust-tasks/did-management/did/check-name/0.1/payload";
import type * as DidRegister from "./trust-tasks/did-management/did/register/0.1/payload";
import type * as DidDelete from "./trust-tasks/did-management/did/delete/0.1/payload";
import type * as DidChangeOwner from "./trust-tasks/did-management/did/change-owner/0.1/payload";
import type * as DidRollback from "./trust-tasks/did-management/did/rollback/0.1/payload";
import type * as DidSetState from "./trust-tasks/did-management/did/set-state/0.1/payload";
import type * as WitnessPublish from "./trust-tasks/webvh/witness/publish/0.1/payload";
import type * as AgentNameCheck from "./trust-tasks/did-management/agent-name/check/0.1/payload";
import type * as AgentNameResolve from "./trust-tasks/did-management/agent-name/resolve/0.1/payload";
import type * as DomainList from "./trust-tasks/did-management/domain/list/0.1/payload";
import type * as MeDomains from "./trust-tasks/did-management/me/domains/0.1/payload";
import type * as DomainCreate from "./trust-tasks/did-management/domain/create/0.1/payload";
import type * as DomainSetState from "./trust-tasks/did-management/domain/set-state/0.1/payload";
import type * as DomainUpdate from "./trust-tasks/did-management/domain/update/0.1/payload";
import type * as StatsSetResolution from "./trust-tasks/did-management/stats/set-resolution/0.1/payload";
import type * as DomainSetDefault from "./trust-tasks/did-management/domain/set-default/0.1/payload";
import type * as DomainPurge from "./trust-tasks/did-management/domain/purge/0.1/payload";
import type * as DomainAssign from "./trust-tasks/did-management/domain/assign/0.1/payload";
import type * as DomainUnassign from "./trust-tasks/did-management/domain/unassign/0.1/payload";
import type * as RegistryList from "./trust-tasks/did-management/registry/list/0.2/payload";
import type * as RegistryPurgeDomain from "./trust-tasks/did-management/registry/purge-domain/0.1/payload";
import type * as StatsGet from "./trust-tasks/did-management/stats/get/0.1/payload";
import type * as StatsTimeseries from "./trust-tasks/did-management/stats/timeseries/0.2/payload";
import type * as ServerConfig from "./trust-tasks/did-management/server/config/0.1/payload";
import type * as IdentityList from "./trust-tasks/did-management/identity/list/0.1/payload";
import type * as IdentityRetire from "./trust-tasks/did-management/identity/retire/0.1/payload";
import type * as LoginStart from "./trust-tasks/auth/passkey/login/start/0.2/payload";
import type * as LoginFinish from "./trust-tasks/auth/passkey/login/finish/0.2/payload";
import type * as Invite from "./trust-tasks/auth/passkey/enroll/invite/0.3/payload";
import type * as RedeemStart from "./trust-tasks/auth/passkey/enroll/redeem/start/0.1/payload";
import type * as RedeemFinish from "./trust-tasks/auth/passkey/enroll/redeem/finish/0.1/payload";
import type * as InviteList from "./trust-tasks/auth/passkey/enroll/invite/list/0.1/payload";
import type * as InviteUpdate from "./trust-tasks/auth/passkey/enroll/invite/update/0.1/payload";
import type * as InviteRevoke from "./trust-tasks/auth/passkey/enroll/invite/revoke/0.1/payload";
import type * as PasskeyList from "./trust-tasks/auth/passkey/list/0.1/payload";
import type * as PasskeyAdminList from "./trust-tasks/auth/passkey/admin-list/0.1/payload";
import type * as PasskeyRevokeStart from "./trust-tasks/auth/passkey/revoke/start/0.2/payload";
import type * as PasskeyRevokeFinish from "./trust-tasks/auth/passkey/revoke/finish/0.2/payload";
import type * as AclList from "./trust-tasks/acl/list/0.3/payload";
import type * as AclShow from "./trust-tasks/acl/show/0.2/payload";
import type * as AclGrant from "./trust-tasks/acl/grant/0.2/payload";
import type * as AclRevoke from "./trust-tasks/acl/revoke/0.2/payload";
import type * as AclChangeRole from "./trust-tasks/acl/change-role/0.2/payload";
import type * as RevokeSession from "./trust-tasks/auth/revoke-session/0.2/payload";
import type * as StepUpStart from "./trust-tasks/auth/step-up/start/0.2/payload";
import type * as StepUpApprove from "./trust-tasks/auth/step-up/approve-response/0.7/payload";
import type * as StepUpApproveRequest from "./trust-tasks/auth/step-up/approve-request/0.5/payload";
import type * as ServerInfo from "./trust-tasks/did-management/server/info/0.1/payload";
import type * as Refresh from "./trust-tasks/auth/refresh/0.2/payload";
import type * as Authenticate from "./trust-tasks/auth/authenticate/0.3/payload";

const TT = "https://trusttasks.org/spec/";
const DM = `${TT}did-management/` as const;

export const T = {
  serverInfo: `${DM}server/info/0.1` as const satisfies typeof ServerInfo.TYPE_URI,
  authenticate: `${TT}auth/authenticate/0.3` as const satisfies typeof Authenticate.TYPE_URI,
  refresh: `${TT}auth/refresh/0.2` as const satisfies typeof Refresh.TYPE_URI,
  didList: `${DM}did/list/0.2` as const satisfies typeof DidList.TYPE_URI,
  didInfo: `${DM}did/info/0.1` as const satisfies typeof DidInfo.TYPE_URI,
  didLog: `${DM}did/log/0.1` as const satisfies typeof DidLog.TYPE_URI,
  didCheckName: `${DM}did/check-name/0.1` as const satisfies typeof DidCheckName.TYPE_URI,
  didRegister: `${DM}did/register/0.1` as const satisfies typeof DidRegister.TYPE_URI,
  didDelete: `${DM}did/delete/0.1` as const satisfies typeof DidDelete.TYPE_URI,
  didChangeOwner: `${DM}did/change-owner/0.1` as const satisfies typeof DidChangeOwner.TYPE_URI,
  didRollback: `${DM}did/rollback/0.1` as const satisfies typeof DidRollback.TYPE_URI,
  didSetState: `${DM}did/set-state/0.1` as const satisfies typeof DidSetState.TYPE_URI,
  witnessPublish:
    `${TT}webvh/witness/publish/0.1` as const satisfies typeof WitnessPublish.TYPE_URI,
  agentNameCheck: `${DM}agent-name/check/0.1` as const satisfies typeof AgentNameCheck.TYPE_URI,
  agentNameResolve:
    `${DM}agent-name/resolve/0.1` as const satisfies typeof AgentNameResolve.TYPE_URI,
  domainList: `${DM}domain/list/0.1` as const satisfies typeof DomainList.TYPE_URI,
  meDomains: `${DM}me/domains/0.1` as const satisfies typeof MeDomains.TYPE_URI,
  domainCreate: `${DM}domain/create/0.1` as const satisfies typeof DomainCreate.TYPE_URI,
  domainSetState: `${DM}domain/set-state/0.1` as const satisfies typeof DomainSetState.TYPE_URI,
  domainUpdate: `${DM}domain/update/0.1` as const satisfies typeof DomainUpdate.TYPE_URI,
  domainSetDefault:
    `${DM}domain/set-default/0.1` as const satisfies typeof DomainSetDefault.TYPE_URI,
  domainPurge: `${DM}domain/purge/0.1` as const satisfies typeof DomainPurge.TYPE_URI,
  domainAssign: `${DM}domain/assign/0.1` as const satisfies typeof DomainAssign.TYPE_URI,
  domainUnassign: `${DM}domain/unassign/0.1` as const satisfies typeof DomainUnassign.TYPE_URI,
  registryList: `${DM}registry/list/0.2` as const satisfies typeof RegistryList.TYPE_URI,
  registryPurgeDomain:
    `${DM}registry/purge-domain/0.1` as const satisfies typeof RegistryPurgeDomain.TYPE_URI,
  statsGet: `${DM}stats/get/0.1` as const satisfies typeof StatsGet.TYPE_URI,
  statsSetResolution:
    `${DM}stats/set-resolution/0.1` as const satisfies typeof StatsSetResolution.TYPE_URI,
  statsTimeseries: `${DM}stats/timeseries/0.2` as const satisfies typeof StatsTimeseries.TYPE_URI,
  serverConfig: `${DM}server/config/0.1` as const satisfies typeof ServerConfig.TYPE_URI,
  identityList: `${DM}identity/list/0.1` as const satisfies typeof IdentityList.TYPE_URI,
  identityRetire: `${DM}identity/retire/0.1` as const satisfies typeof IdentityRetire.TYPE_URI,
  loginStart: `${TT}auth/passkey/login/start/0.2` as const satisfies typeof LoginStart.TYPE_URI,
  loginFinish: `${TT}auth/passkey/login/finish/0.2` as const satisfies typeof LoginFinish.TYPE_URI,
  invite: `${TT}auth/passkey/enroll/invite/0.3` as const satisfies typeof Invite.TYPE_URI,
  redeemStart:
    `${TT}auth/passkey/enroll/redeem/start/0.1` as const satisfies typeof RedeemStart.TYPE_URI,
  redeemFinish:
    `${TT}auth/passkey/enroll/redeem/finish/0.1` as const satisfies typeof RedeemFinish.TYPE_URI,
  inviteList:
    `${TT}auth/passkey/enroll/invite/list/0.1` as const satisfies typeof InviteList.TYPE_URI,
  inviteUpdate:
    `${TT}auth/passkey/enroll/invite/update/0.1` as const satisfies typeof InviteUpdate.TYPE_URI,
  inviteRevoke:
    `${TT}auth/passkey/enroll/invite/revoke/0.1` as const satisfies typeof InviteRevoke.TYPE_URI,
  passkeyList: `${TT}auth/passkey/list/0.1` as const satisfies typeof PasskeyList.TYPE_URI,
  passkeyAdminList:
    `${TT}auth/passkey/admin-list/0.1` as const satisfies typeof PasskeyAdminList.TYPE_URI,
  passkeyRevokeStart:
    `${TT}auth/passkey/revoke/start/0.2` as const satisfies typeof PasskeyRevokeStart.TYPE_URI,
  passkeyRevokeFinish:
    `${TT}auth/passkey/revoke/finish/0.2` as const satisfies typeof PasskeyRevokeFinish.TYPE_URI,
  aclList: `${TT}acl/list/0.3` as const satisfies typeof AclList.TYPE_URI,
  revokeSession: `${TT}auth/revoke-session/0.2` as const satisfies typeof RevokeSession.TYPE_URI,
  stepUpStart: `${TT}auth/step-up/start/0.2` as const satisfies typeof StepUpStart.TYPE_URI,
  stepUpApproveRequest:
    `${TT}auth/step-up/approve-request/0.5` as const satisfies typeof StepUpApproveRequest.TYPE_URI,
  stepUpApproveResponse:
    `${TT}auth/step-up/approve-response/0.7` as const satisfies typeof StepUpApprove.TYPE_URI,
  aclShow: `${TT}acl/show/0.2` as const satisfies typeof AclShow.TYPE_URI,
  aclGrant: `${TT}acl/grant/0.2` as const satisfies typeof AclGrant.TYPE_URI,
  aclRevoke: `${TT}acl/revoke/0.2` as const satisfies typeof AclRevoke.TYPE_URI,
  aclChangeRole: `${TT}acl/change-role/0.2` as const satisfies typeof AclChangeRole.TYPE_URI,
} as const;
