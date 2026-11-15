/** Hosting domains. */

import type * as DomainList from "../trust-tasks/did-management/domain/list/0.1/payload";
import type * as MeDomains from "../trust-tasks/did-management/me/domains/0.1/payload";
import type * as DomainCreate from "../trust-tasks/did-management/domain/create/0.1/payload";
import type * as DomainSetState from "../trust-tasks/did-management/domain/set-state/0.1/payload";
import type * as DomainUpdate from "../trust-tasks/did-management/domain/update/0.1/payload";
import type * as DomainSetDefault from "../trust-tasks/did-management/domain/set-default/0.1/payload";
import type * as DomainPurge from "../trust-tasks/did-management/domain/purge/0.1/payload";
import { trustTask } from "../trust-task";
import { domainFromWire } from "../wire";
import { withStepUp } from "./auth";
import { T } from "./tasks";
import type { DomainEntry, DomainListResponse } from "./types";

export const domainsApi = {
  // ---- Hosting domains ----

  /** Every domain. Admin. */
  listDomains: async (): Promise<DomainListResponse> => {
    const r = await trustTask<DomainList.Payload, DomainList.Response>(T.domainList, {});
    return {
      domains: r.domains.map((d) => domainFromWire(d)),
      default: r.default ?? null,
    };
  },

  /** The caller's domains, with the caller's default. */
  listMyDomains: async (): Promise<DomainListResponse> => {
    const r = await trustTask<MeDomains.Payload, MeDomains.Response>(T.meDomains, {});
    return {
      domains: r.domains.map((d) => domainFromWire(d)),
      default: r.default ?? null,
    };
  },

  /** Create a domain; `setAsDefault` promotes it in the same call. Admin. */
  createDomain: async (input: {
    name: string;
    label?: string;
    setAsDefault?: boolean;
  }): Promise<DomainEntry> => {
    const r = await trustTask<DomainCreate.Payload, DomainCreate.Response>(T.domainCreate, {
      name: input.name,
      ...(input.label ? { label: input.label } : {}),
      ...(input.setAsDefault ? { setAsDefault: true } : {}),
    });
    return domainFromWire(r.entry);
  },

  /** Change a domain's friendly label. Admin. */
  updateDomainLabel: async (name: string, label: string): Promise<DomainEntry> =>
    domainFromWire(
      (
        await trustTask<DomainUpdate.Payload, DomainUpdate.Response>(T.domainUpdate, {
          name,
          label,
        })
      ).entry,
    ),

  disableDomain: async (name: string): Promise<DomainEntry> =>
    domainFromWire(
      (
        await trustTask<DomainSetState.Payload, DomainSetState.Response>(T.domainSetState, {
          name,
          state: "disabled",
        })
      ).entry,
    ),

  enableDomain: async (name: string): Promise<DomainEntry> =>
    domainFromWire(
      (
        await trustTask<DomainSetState.Payload, DomainSetState.Response>(T.domainSetState, {
          name,
          state: "active",
        })
      ).entry,
    ),

  setDefaultDomain: async (name: string): Promise<DomainEntry> =>
    domainFromWire(
      (
        await trustTask<DomainSetDefault.Payload, DomainSetDefault.Response>(T.domainSetDefault, {
          name,
        })
      ).entry,
    ),

  /**
   * Force-delete a disabled domain now, ahead of its grace window. Refused
   * while the domain is active or the default.
   *
   * Needs a stepped-up (`aal2`) session. A passkey login already is one; a
   * wallet session is stepped up through the wallet when the control plane
   * asks for it, and the purge is then sent once more.
   *
   * `purgeServers` also sends the purge to every edge serving the domain.
   */
  deleteDomain: async (name: string, opts?: { purgeServers?: boolean }): Promise<void> => {
    await withStepUp(() =>
      trustTask<DomainPurge.Payload, DomainPurge.Response>(T.domainPurge, {
        name,
        ...(opts?.purgeServers ? { purgeServers: true } : {}),
      }),
    );
  },
};
