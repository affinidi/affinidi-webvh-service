/**
 * The service itself: liveness, its identity generations, stats, its
 * configuration and the registry of edges it serves through.
 */

import type * as DomainAssign from "../trust-tasks/did-management/domain/assign/0.1/payload";
import type * as DomainUnassign from "../trust-tasks/did-management/domain/unassign/0.1/payload";
import type * as RegistryList from "../trust-tasks/did-management/registry/list/0.2/payload";
import type * as RegistryPurgeDomain from "../trust-tasks/did-management/registry/purge-domain/0.1/payload";
import type * as StatsGet from "../trust-tasks/did-management/stats/get/0.1/payload";
import type * as StatsSetResolution from "../trust-tasks/did-management/stats/set-resolution/0.1/payload";
import type * as StatsTimeseries from "../trust-tasks/did-management/stats/timeseries/0.2/payload";
import type * as ServerConfig from "../trust-tasks/did-management/server/config/0.1/payload";
import type * as IdentityList from "../trust-tasks/did-management/identity/list/0.1/payload";
import type * as IdentityRetire from "../trust-tasks/did-management/identity/retire/0.1/payload";
import type { Response as ServerInfo } from "../trust-tasks/did-management/server/info/0.1/payload";
import { request } from "../http";
import { getServiceInfo, trustTask } from "../trust-task";
import {
  configFromWire,
  identityFromWire,
  serviceInstanceFromWire,
  statsFromWire,
  timeRangeToWire,
  timeseriesFromWire,
  WEBVH_EXT,
} from "../wire";
import { withStepUp } from "./auth";
import { T } from "./tasks";
import type {
  ControlPlaneConfig,
  DidStats,
  HealthResponse,
  IdentityGenerationsResponse,
  ServerStats,
  ServiceInstance,
  ServiceOverview,
  TimeRange,
  TimeSeriesPoint,
} from "./types";
import type { ReadOptions } from "./tasks";

/**
 * The service overview the dashboard shows, from its three reads. Pure, so a
 * screen that already holds the reads (cached, polled) composes it without a
 * fourth request.
 */
export function buildServiceOverview(
  config: ControlPlaneConfig,
  services: ServiceInstance[],
  stats: ServerStats,
): ServiceOverview {
  const count = (s: ServiceInstance["status"]) => services.filter((i) => i.status === s).length;
  return {
    control: {
      version: config.softwareVersion,
      serverDid: config.controlDid,
      publicUrl: config.publicUrl,
      didcommEnabled: config.didcommEnabled,
      tspEnabled: config.tspEnabled,
      ...(config.advertisedServices ? { advertisedServices: config.advertisedServices } : {}),
      enabledMethods: config.enabledMethods,
    },
    services,
    aggregate: {
      totalServices: services.length,
      activeServices: count("active"),
      degradedServices: count("degraded"),
      unreachableServices: count("unreachable"),
      totalDids: stats.totalDids,
      totalResolves: stats.totalResolves,
      totalUpdates: stats.totalUpdates,
    },
  };
}

export const serviceApi = {
  /** Unauthenticated liveness probe. Plain HTTP by design. */
  health: () => request<HealthResponse>("/api/health", { anonymous: true }),

  /** `server/info`: the service DID and the public facts shown before login. */
  serverInfo: (): Promise<ServerInfo> => getServiceInfo(),

  // ---- The service's own identity ----

  listIdentityGenerations: async (): Promise<IdentityGenerationsResponse> =>
    identityFromWire(
      await trustTask<IdentityList.Payload, IdentityList.Response>(T.identityList, {}),
    ),

  /**
   * Stop honouring a superseded generation immediately — the kill switch.
   * The key is dropped from the live secrets resolver before this returns.
   * Needs a stepped-up session (`withStepUp`).
   */
  retireIdentityGeneration: async (id: number): Promise<void> => {
    await withStepUp(() =>
      trustTask<IdentityRetire.Payload, IdentityRetire.Response>(T.identityRetire, {
        generationId: id,
      }),
    );
  },

  // ---- Stats ----

  /**
   * How much statistical detail to keep over time for one DID: `auto` (the
   * service decides from its traffic), `fine` (5-minute series; admin only),
   * `coarse` (hourly and daily only) or `off` (totals only).
   */
  setStatsResolution: async (
    mnemonic: string,
    resolution: StatsSetResolution.Payload["resolution"],
  ): Promise<StatsSetResolution.Response> =>
    trustTask<StatsSetResolution.Payload, StatsSetResolution.Response>(T.statsSetResolution, {
      mnemonic,
      resolution,
    }),

  getStats: async (mnemonic: string, opts: ReadOptions = {}): Promise<DidStats> =>
    statsFromWire(
      await trustTask<StatsGet.Payload, StatsGet.Response>(T.statsGet, { mnemonic }, opts),
    ),

  getServerStats: async (opts: ReadOptions = {}): Promise<ServerStats> =>
    statsFromWire(await trustTask<StatsGet.Payload, StatsGet.Response>(T.statsGet, {}, opts)),

  /** One domain's totals (`stats/get` with the webvh `domain` extension):
   *  every slot on it for an admin, the caller's own for anyone else. One
   *  request, however many DIDs the domain holds. */
  getDomainStats: async (domain: string, opts: ReadOptions = {}): Promise<ServerStats> =>
    statsFromWire(
      await trustTask<StatsGet.Payload, StatsGet.Response>(
        T.statsGet,
        { ext: { [WEBVH_EXT]: { domain } } },
        opts,
      ),
    ),

  getServerTimeseries: async (
    range: TimeRange = "24h",
    domain?: string,
    opts: ReadOptions = {},
  ): Promise<TimeSeriesPoint[]> =>
    timeseriesFromWire(
      await trustTask<StatsTimeseries.Payload, StatsTimeseries.Response>(
        T.statsTimeseries,
        {
          range: timeRangeToWire(range),
          ...(domain ? { domain } : {}),
        },
        opts,
      ),
    ),

  getDidTimeseries: async (
    mnemonic: string,
    range: TimeRange = "24h",
    opts: ReadOptions = {},
  ): Promise<TimeSeriesPoint[]> =>
    timeseriesFromWire(
      await trustTask<StatsTimeseries.Payload, StatsTimeseries.Response>(
        T.statsTimeseries,
        { range: timeRangeToWire(range), mnemonic },
        opts,
      ),
    ),

  // ---- The deployment ----

  getConfig: async (opts: ReadOptions = {}): Promise<ControlPlaneConfig> =>
    configFromWire(
      await trustTask<ServerConfig.Payload, ServerConfig.Response>(T.serverConfig, {}, opts),
    ),

  /** Control plane + fleet + totals, for the dashboard. Admin. */
  getServicesOverview: async (opts: ReadOptions = {}): Promise<ServiceOverview> => {
    const [config, services, stats] = await Promise.all([
      serviceApi.getConfig(opts),
      serviceApi.listRegistry(opts),
      serviceApi.getServerStats(opts),
    ]);
    return buildServiceOverview(config, services, stats);
  },

  listRegistry: async (opts: ReadOptions = {}): Promise<ServiceInstance[]> =>
    (
      await trustTask<RegistryList.Payload, RegistryList.Response>(T.registryList, {}, opts)
    ).instances.map(serviceInstanceFromWire),

  /** Assign a hosting domain to a server instance; the control plane queues
   *  the directive to the edge. */
  assignDomainToServer: async (instanceId: string, domain: string): Promise<void> => {
    await trustTask<DomainAssign.Payload, DomainAssign.Response>(T.domainAssign, {
      instanceId,
      domain,
    });
  },

  /** Unassign; the edge schedules its purge after its grace period. */
  unassignDomainFromServer: async (instanceId: string, domain: string): Promise<void> => {
    await trustTask<DomainUnassign.Payload, DomainUnassign.Response>(T.domainUnassign, {
      instanceId,
      domain,
    });
  },

  /** Admin "Purge now" on one edge. Refused while the domain is still
   *  assigned to that edge (`stillAssigned`). Needs a stepped-up session
   *  (`withStepUp`). */
  purgeDomainOnServer: async (instanceId: string, domain: string): Promise<void> => {
    await withStepUp(() =>
      trustTask<RegistryPurgeDomain.Payload, RegistryPurgeDomain.Response>(T.registryPurgeDomain, {
        instanceId,
        domain,
      }),
    );
  },
};
