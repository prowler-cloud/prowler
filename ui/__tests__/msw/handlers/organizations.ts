/**
 * MSW handlers for the organization onboarding flow.
 *
 * These serve BOTH the deprecated `/organizational-units` routes and the
 * canonical `/organization-nodes` routes over the same fixture data. AWS
 * bodies carry canonical fields plus the deprecated aliases, mirroring an API
 * that still accepts both. Set the fixture flag `serveDeprecatedRoutes` to
 * `false` to drop the alias routes — used to assert no UI code still calls
 * them.
 *
 * Wire the handlers per test via `worker.use(...handlersForOrganizations(fx))`.
 * The module also doubles as the no-backend dev harness.
 */

import { http, HttpResponse } from "msw";

import { NODE_KIND } from "./organizations.fixtures";
import type {
  FixtureNode,
  FixtureOrganization,
  FixtureProvider,
  OrgFixture,
} from "./organizations.fixtures";

const API = process.env.UI_API_BASE_URL;
const TS = "2026-07-01T10:00:00Z";

type JsonApiError = { errors: Array<{ detail: string; status: string }> };

const errorBody = (detail: string, status: number): JsonApiError => ({
  errors: [{ detail, status: String(status) }],
});

const providerRefs = (ids: string[]) =>
  ids.map((id) => ({ type: "providers", id }));

interface OrgResourceOptions {
  /** Emit the deprecated `organizational_units` alias alongside canonical. */
  includeAliases: boolean;
  /**
   * Node ids to surface under the deprecated `organizational_units` alias.
   * Only organizational-unit-kind nodes belong here — the deprecated route
   * never surfaced GCP folders.
   */
  unitNodeIds: string[];
}

const organizationResource = (
  org: FixtureOrganization,
  { includeAliases, unitNodeIds }: OrgResourceOptions,
) => ({
  id: org.id,
  type: "organizations",
  attributes: {
    name: org.name,
    org_type: org.orgType,
    external_id: org.externalId,
    metadata: {},
    root_external_id: org.rootExternalId,
    inserted_at: TS,
    updated_at: TS,
  },
  relationships: {
    providers: { data: providerRefs(org.providerIds) },
    organization_nodes: {
      data: org.nodeIds.map((id) => ({ type: "organization-nodes", id })),
    },
    // Deprecated alias, gated on `includeAwsAliases`.
    ...(includeAliases && {
      organizational_units: {
        data: unitNodeIds.map((id) => ({ type: "organizational-units", id })),
      },
    }),
  },
});

/**
 * Canonical `organization-nodes` resource (carries `kind`).
 *
 * The parent is a relationship, not an attribute, and DJA always emits the key —
 * `data: null` for a top-level node, since neither the AWS root nor a GCP
 * organization is itself a node. Fixtures still express structure as
 * `parentExternalId`, resolved to a node ref here.
 */
const organizationNodeResource = (node: FixtureNode, all: FixtureNode[]) => {
  const parent = all.find(
    (candidate) =>
      candidate.organizationId === node.organizationId &&
      candidate.externalId === node.parentExternalId,
  );

  return {
    id: node.id,
    type: "organization-nodes",
    attributes: {
      name: node.name,
      kind: node.kind,
      external_id: node.externalId,
      metadata: {},
      inserted_at: TS,
      updated_at: TS,
    },
    relationships: {
      organization: {
        data: { type: "organizations", id: node.organizationId },
      },
      parent: {
        data: parent ? { type: "organization-nodes", id: parent.id } : null,
      },
      providers: { data: providerRefs(node.providerIds) },
    },
  };
};

/** Deprecated AWS-only `organizational-units` resource (no `kind`). */
const organizationalUnitResource = (node: FixtureNode) => ({
  id: node.id,
  type: "organizational-units",
  attributes: {
    name: node.name,
    external_id: node.externalId,
    parent_external_id: node.parentExternalId,
    metadata: {},
    inserted_at: TS,
    updated_at: TS,
  },
  relationships: {
    organization: {
      data: { type: "organizations", id: node.organizationId },
    },
    providers: { data: providerRefs(node.providerIds) },
  },
});

/** Single-page collection meta, enough for the paginating list actions to stop. */
const collectionMeta = (count: number) => ({
  pagination: { page: 1, pages: 1, count },
  version: "v1",
});

/**
 * Full `providers` list resource, as the providers-page loader consumes it.
 * Deliberately carries no `scan_*` attributes: the API omits them unless a
 * schedule is configured, and their absence is what makes the loader fall back
 * to `/schedules`.
 */
const providerResource = (provider: FixtureProvider) => ({
  id: provider.id,
  type: "providers",
  attributes: {
    provider: provider.provider,
    is_dynamic: false,
    uid: provider.uid,
    alias: provider.alias,
    status: "completed",
    resources: 0,
    connection: {
      connected: provider.connected ?? false,
      last_checked_at: TS,
    },
    scanner_args: {
      only_logs: false,
      excluded_checks: [],
      aws_retries_max_attempts: 3,
    },
    inserted_at: TS,
    updated_at: TS,
    created_by: { object: "user", id: "user-1" },
  },
  relationships: {
    secret: { data: { type: "secrets", id: `secret-${provider.id}` } },
    provider_groups: { meta: { count: 0 }, data: [] },
  },
});

/**
 * Serves a collection the way the paginated API does: honours
 * `page[number]`/`page[size]` and reports `meta.pagination.pages`, so a caller
 * that stops after the first page visibly loses the rest.
 */
const paginatedCollection = <T>(items: T[], request: Request) => {
  const params = new URL(request.url).searchParams;
  const size = Number(params.get("page[size]")) || items.length || 1;
  const page = Number(params.get("page[number]")) || 1;
  const start = (page - 1) * size;

  return {
    data: items.slice(start, start + size),
    meta: {
      version: "v1",
      pagination: {
        page,
        pages: Math.max(1, Math.ceil(items.length / size)),
        count: items.length,
      },
    },
  };
};

/**
 * Map a created-provider id back to its uid (AWS account id / GCP project id).
 * `apply.candidateProviderIds` is a fixture-side mapping, not a wire field.
 */
const uidForProviderId = (
  fx: OrgFixture,
  providerId: string,
): string | null => {
  const mapping = fx.apply.candidateProviderIds.find(
    (m) => m.providerId === providerId,
  );
  if (mapping) return mapping.candidateId;
  const provider = fx.providers.find((p) => p.id === providerId);
  return provider?.uid ?? null;
};

/**
 * The provider behind an id, seeded or apply-created. A created provider exists
 * only as an id plus its candidate mapping, so the rest is synthesized as
 * `/providers/:id` does; only `id` and `uid` are ever read back.
 */
const providerForId = (fx: OrgFixture, id: string): FixtureProvider => {
  const seeded = fx.providers.find((provider) => provider.id === id);
  if (seeded) return seeded;

  const uid = uidForProviderId(fx, id) ?? id;
  return { id, provider: "aws", uid, alias: uid, connected: true };
};

const applyResultResponse = (fx: OrgFixture) => ({
  data: {
    id: "apply-result-1",
    type: "organization-discovery-apply-results",
    attributes: {
      providers_created_count: fx.apply.providersCreatedCount,
      providers_linked_count: fx.apply.providersLinkedCount,
      providers_applied_count:
        fx.apply.providersCreatedCount + fx.apply.providersLinkedCount,
      organization_nodes_created_count: fx.apply.nodesCreatedCount,
      // Deprecated counter alias, gated on `includeAwsAliases`.
      ...(fx.includeAwsAliases && {
        organizational_units_created_count: fx.apply.nodesCreatedCount,
      }),
    },
    relationships: {
      providers: {
        data: providerRefs(fx.apply.createdProviderIds),
        meta: { count: fx.apply.createdProviderIds.length },
      },
      organization_nodes: {
        data: [],
        meta: { count: fx.apply.nodesCreatedCount },
      },
      // Deprecated relationship alias, gated on `includeAwsAliases`.
      ...(fx.includeAwsAliases && {
        organizational_units: {
          data: [],
          meta: { count: fx.apply.nodesCreatedCount },
        },
      }),
    },
  },
  // No `included`: the apply view serves provider ids only and rejects `include`,
  // so the created providers' uids are read from `/providers` afterwards.
});

const taskResource = (id: string, state: string, result: unknown) => ({
  data: { id, type: "tasks", attributes: { state, result } },
});

const CONNECTION_TASK_PREFIX = "conn-task-";
const DELETION_TASK_PREFIX = "del-task-";

interface HandlerOptions {
  /**
   * Which hierarchy read 500s. The `…Safe` actions turn that into their
   * degraded flag and the page derives `hierarchyStatus` — never an injected
   * prop.
   */
  hierarchyFailure?: HierarchyReadFailure;
}

export const HIERARCHY_READ_FAILURE = {
  NONE: "none",
  /** Both `/organizations` and `/organization-nodes` fail. */
  ALL: "all",
  /** Only `/organization-nodes` fails. */
  NODES: "nodes",
} as const;

export type HierarchyReadFailure =
  (typeof HIERARCHY_READ_FAILURE)[keyof typeof HIERARCHY_READ_FAILURE];

export const handlersForOrganizations = (
  fx: OrgFixture,
  { hierarchyFailure = HIERARCHY_READ_FAILURE.NONE }: HandlerOptions = {},
) => {
  const organizationReadFails = hierarchyFailure === HIERARCHY_READ_FAILURE.ALL;
  const nodeReadFails = hierarchyFailure !== HIERARCHY_READ_FAILURE.NONE;
  // Mutable working copy for resources created during the test lifecycle.
  const organizations = [...fx.organizations];
  const createdSecretIds = new Set(
    organizations.map((o) => o.secretId).filter((id): id is string => !!id),
  );
  let orgSeq = 0;
  let secretSeq = 0;
  /** Reads per connection task, so `executingPolls` can hold one task running. */
  const connectionTaskReads = new Map<string, number>();

  const unitNodeIds = (org: FixtureOrganization): string[] =>
    org.nodeIds.filter((id) =>
      fx.nodes.some(
        (n) => n.id === id && n.kind === NODE_KIND.ORGANIZATIONAL_UNIT,
      ),
    );
  const orgResource = (org: FixtureOrganization) =>
    organizationResource(org, {
      includeAliases: fx.includeAwsAliases,
      unitNodeIds: unitNodeIds(org),
    });

  const handlers = [
    // --- organizations CRUD + filters ------------------------------------
    http.get(`${API}/organizations`, ({ request }) => {
      if (organizationReadFails) {
        return HttpResponse.json(errorBody("Hierarchy unavailable", 500), {
          status: 500,
        });
      }
      const url = new URL(request.url);
      const externalId = url.searchParams.get("filter[external_id]");
      const orgType = url.searchParams.get("filter[org_type]");
      const matches = organizations
        .filter((o) => (externalId ? o.externalId === externalId : true))
        .filter((o) => (orgType ? o.orgType === orgType : true))
        .map(orgResource);
      return HttpResponse.json(paginatedCollection(matches, request));
    }),

    http.post(`${API}/organizations`, async ({ request }) => {
      const body = (await request.json()) as {
        data?: { attributes?: Record<string, unknown> };
      };
      const attrs = body?.data?.attributes ?? {};
      orgSeq += 1;
      const created: FixtureOrganization = {
        id: `org-created-${orgSeq}`,
        orgType: String(attrs.org_type ?? "aws"),
        name: String(attrs.name ?? ""),
        externalId: String(attrs.external_id ?? ""),
        // Writable on POST for Azure (the target Management Group); AWS and GCP
        // leave it to discovery and send nothing.
        rootExternalId: attrs.root_external_id
          ? String(attrs.root_external_id)
          : null,
        providerIds: [],
        nodeIds: [],
        secretId: null,
      };
      organizations.push(created);
      return HttpResponse.json({ data: orgResource(created) }, { status: 201 });
    }),

    http.patch<{ id: string }>(
      `${API}/organizations/:id`,
      async ({ params, request }) => {
        const body = (await request.json()) as {
          data?: { attributes?: { name?: string } };
        };
        const org = organizations.find((o) => o.id === params.id);
        if (!org) {
          return HttpResponse.json(errorBody("Not found", 404), {
            status: 404,
          });
        }
        org.name = body?.data?.attributes?.name ?? org.name;
        return HttpResponse.json({ data: orgResource(org) });
      },
    ),

    http.delete<{ id: string }>(`${API}/organizations/:id`, ({ params }) =>
      HttpResponse.json(
        taskResource(`${DELETION_TASK_PREFIX}${params.id}`, "executing", null),
        { status: 202 },
      ),
    ),

    // --- organization-secrets --------------------------------------------
    http.get(`${API}/organization-secrets`, ({ request }) => {
      const url = new URL(request.url);
      const orgId = url.searchParams.get("filter[organization_id]");
      const org = organizations.find((o) => o.id === orgId);
      const data = org?.secretId
        ? [
            {
              id: org.secretId,
              type: "organization-secrets",
              attributes: { secret_type: "role" },
            },
          ]
        : [];
      return HttpResponse.json({ data });
    }),

    http.post(`${API}/organization-secrets`, async ({ request }) => {
      const body = (await request.json()) as {
        data?: {
          attributes?: { secret_type?: string };
          relationships?: {
            organization?: { data?: { id?: string } };
          };
        };
      };
      const orgId = body?.data?.relationships?.organization?.data?.id;
      const org = organizations.find((o) => o.id === orgId);
      if (fx.duplicateSecret || org?.secretId) {
        return HttpResponse.json(
          errorBody("A secret for this organization already exists.", 409),
          { status: 409 },
        );
      }
      secretSeq += 1;
      const secretId = `secret-created-${secretSeq}`;
      createdSecretIds.add(secretId);
      if (org) org.secretId = secretId;
      return HttpResponse.json(
        {
          data: {
            id: secretId,
            type: "organization-secrets",
            attributes: {
              secret_type: body?.data?.attributes?.secret_type ?? "role",
            },
          },
        },
        { status: 201 },
      );
    }),

    http.patch<{ id: string }>(
      `${API}/organization-secrets/:id`,
      ({ params }) =>
        HttpResponse.json({
          data: { id: params.id, type: "organization-secrets" },
        }),
    ),

    // --- canonical organization-nodes ------------------------------------
    http.get(`${API}/organization-nodes`, ({ request }) =>
      nodeReadFails
        ? HttpResponse.json(errorBody("Hierarchy unavailable", 500), {
            status: 500,
          })
        : HttpResponse.json(
            paginatedCollection(
              fx.nodes.map((node) => organizationNodeResource(node, fx.nodes)),
              request,
            ),
          ),
    ),

    http.delete<{ id: string }>(`${API}/organization-nodes/:id`, ({ params }) =>
      HttpResponse.json(
        taskResource(`${DELETION_TASK_PREFIX}${params.id}`, "executing", null),
        { status: 202 },
      ),
    ),

    // --- discovery -------------------------------------------------------
    http.post<{ orgId: string }>(`${API}/organizations/:orgId/discover`, () => {
      if (!fx.discovery) {
        return HttpResponse.json(errorBody("Discovery unavailable", 409), {
          status: 409,
        });
      }
      return HttpResponse.json(
        {
          data: {
            id: fx.discovery.id,
            type: "organization-discoveries",
            attributes: {
              status: "pending",
              result: {},
              error: null,
              inserted_at: TS,
              updated_at: TS,
            },
          },
        },
        { status: 202 },
      );
    }),

    http.get<{ orgId: string; discoveryId: string }>(
      `${API}/organizations/:orgId/discoveries/:discoveryId`,
      ({ params }) => {
        if (!fx.discovery || fx.discovery.id !== params.discoveryId) {
          return HttpResponse.json(errorBody("Discovery not found", 404), {
            status: 404,
          });
        }
        return HttpResponse.json({
          data: {
            id: fx.discovery.id,
            type: "organization-discoveries",
            attributes: {
              status: fx.discovery.status,
              result:
                fx.discovery.status === "succeeded" ? fx.discovery.result : {},
              error: fx.discovery.error,
              // Machine code and human message are separate fields; the message
              // is only sent for the codes the API explains itself.
              error_message: fx.discovery.errorMessage ?? null,
              inserted_at: TS,
              updated_at: TS,
            },
          },
        });
      },
    ),

    http.post<{ orgId: string; discoveryId: string }>(
      `${API}/organizations/:orgId/discoveries/:discoveryId/apply`,
      () => {
        if (fx.apply.error) {
          return HttpResponse.json(
            errorBody(fx.apply.error.detail, fx.apply.error.status),
            { status: fx.apply.error.status },
          );
        }
        return HttpResponse.json(applyResultResponse(fx));
      },
    ),

    // --- providers-page loader (providers list, groups, schedules) --------
    http.get(`${API}/providers`, ({ request }) => {
      // `filter[id__in]` is how the apply flow resolves the uids of the providers
      // it just created. Those are not seeded in `fx.providers`, so they are
      // synthesized here as `/providers/:id` does.
      const idFilter = new URL(request.url).searchParams.get("filter[id__in]");
      const data = idFilter
        ? idFilter
            .split(",")
            .filter(Boolean)
            .map((id) => providerResource(providerForId(fx, id)))
        : fx.providers.map(providerResource);

      return HttpResponse.json({
        data,
        included: [],
        meta: collectionMeta(data.length),
      });
    }),

    http.get(`${API}/provider-groups`, () =>
      HttpResponse.json({ data: [], meta: collectionMeta(0) }),
    ),

    // Schedules are a best-effort fallback for providers without `scan_*`
    // attributes; none of the fixtures seed one.
    http.get(`${API}/schedules`, () =>
      HttpResponse.json({ data: [], meta: collectionMeta(0) }),
    ),

    // Cloud-only scan configurations, fetched alongside the view data.
    http.get(`${API}/scan-configurations`, () =>
      HttpResponse.json({ data: [], meta: collectionMeta(0) }),
    ),

    // --- providers (uid resolution) + connection testing -----------------
    http.get<{ id: string }>(`${API}/providers/:id`, ({ params }) => {
      const provider = fx.providers.find((p) => p.id === params.id);
      const uid = provider?.uid ?? uidForProviderId(fx, params.id) ?? params.id;
      return HttpResponse.json({
        data: {
          id: params.id,
          type: "providers",
          attributes: {
            provider: provider?.provider ?? "aws",
            uid,
            alias: provider?.alias ?? uid,
            connection: {
              connected: provider?.connected ?? true,
              last_checked_at: TS,
            },
          },
        },
      });
    }),

    http.post<{ id: string }>(`${API}/providers/:id/connection`, ({ params }) =>
      HttpResponse.json(
        {
          data: {
            id: `${CONNECTION_TASK_PREFIX}${params.id}`,
            type: "tasks",
            attributes: { state: "executing" },
          },
        },
        { status: 202 },
      ),
    ),

    // --- task polling (deletion + connection) ----------------------------
    http.get<{ taskId: string }>(`${API}/tasks/:taskId`, ({ params }) => {
      const { taskId } = params;
      if (taskId.startsWith(CONNECTION_TASK_PREFIX)) {
        const providerId = taskId.slice(CONNECTION_TASK_PREFIX.length);
        const uid = uidForProviderId(fx, providerId);
        const outcome = uid ? fx.connectionByUid[uid] : undefined;
        const reads = (connectionTaskReads.get(taskId) ?? 0) + 1;
        connectionTaskReads.set(taskId, reads);

        if (outcome?.executingPolls && reads <= outcome.executingPolls) {
          return HttpResponse.json(taskResource(taskId, "executing", {}));
        }

        const connected = outcome?.connected ?? true;
        return HttpResponse.json(
          taskResource(taskId, "completed", {
            connected,
            error: connected ? undefined : outcome?.error,
          }),
        );
      }
      if (taskId.startsWith(DELETION_TASK_PREFIX)) {
        return HttpResponse.json(
          taskResource(taskId, fx.deletionTaskState, {}),
        );
      }
      return HttpResponse.json(taskResource(taskId, "completed", {}));
    }),

    // --- launch (scans + schedules) --------------------------------------
    http.post(`${API}/scans/bulk`, () =>
      HttpResponse.json(
        {
          data: fx.apply.createdProviderIds.map((providerId, index) => ({
            id: `scan-${index + 1}`,
            type: "scans",
            relationships: {
              provider: {
                data: { id: providerId, type: "providers" },
              },
              task: {
                data: { id: `scan-task-${index + 1}`, type: "tasks" },
              },
            },
          })),
        },
        { status: 202 },
      ),
    ),
    http.post(`${API}/schedules`, () =>
      HttpResponse.json(
        { data: { id: "schedule-1", type: "schedules", attributes: {} } },
        { status: 202 },
      ),
    ),
    http.post(`${API}/schedules/bulk`, async ({ request }) => {
      const body = (await request.json()) as {
        data?: { attributes?: { provider_ids?: string[] } };
      };
      const requestedIds = body?.data?.attributes?.provider_ids ?? [];
      const { failed, shape } = fx.scheduleBulk;
      const failedIds = new Set(failed.map((failure) => failure.id));
      // `updated` defaults to the requested ids minus the failures: each provider
      // commits in its own transaction, so the API's list already excludes them.
      const updated =
        fx.scheduleBulk.updated ??
        requestedIds.filter((id) => !failedIds.has(id));

      // The real endpoint returns a plain dict the JSON:API renderer wraps in
      // `data`, with no `attributes` level; the other shapes exercise the client's
      // tolerance of a serializer-rendered body and of one carrying no lists.
      if (shape === "attributes") {
        return HttpResponse.json({
          data: { type: "schedules-bulk", attributes: { updated, failed } },
        });
      }
      if (shape === "bare") {
        return HttpResponse.json({ data: {} });
      }
      return HttpResponse.json({ data: { updated, failed } });
    }),
  ];

  // Deprecated AWS-only routes, served alongside the canonical ones unless
  // `serveDeprecatedRoutes` is off.
  const deprecatedHandlers = [
    http.get(`${API}/organizational-units`, () =>
      HttpResponse.json({
        data: fx.nodes
          .filter((n) => n.kind === NODE_KIND.ORGANIZATIONAL_UNIT)
          .map(organizationalUnitResource),
        meta: { version: "v1" },
      }),
    ),
    http.delete<{ id: string }>(
      `${API}/organizational-units/:id`,
      ({ params }) =>
        HttpResponse.json(
          taskResource(
            `${DELETION_TASK_PREFIX}${params.id}`,
            "executing",
            null,
          ),
          { status: 202 },
        ),
    ),
  ];

  return fx.serveDeprecatedRoutes
    ? [...handlers, ...deprecatedHandlers]
    : handlers;
};
