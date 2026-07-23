/**
 * MSW handlers for the organizations onboarding flow.
 *
 * These serve BOTH the deprecated `/organizational-units` routes and the
 * canonical `/organization-nodes` contract over the same fixture data —
 * exactly like the real transition-window API (see design decision D13). AWS
 * bodies carry canonical fields plus deprecated aliases; the fixture flag
 * `serveDeprecatedRoutes` is flipped off by the Phase 1 tripwire (task 2.10) to
 * prove no UI code still calls alias endpoints.
 *
 * Wire the handlers per test via `worker.use(...handlersForOrganizations(fx))`.
 * The module also doubles as the no-backend dev harness.
 */

import { http, HttpResponse } from "msw";

import type {
  FixtureNode,
  FixtureOrganization,
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

const organizationResource = (org: FixtureOrganization) => ({
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
    // Canonical relationship + deprecated alias, both over the same node ids.
    organization_nodes: {
      data: org.nodeIds.map((id) => ({ type: "organization-nodes", id })),
    },
    organizational_units: {
      data: org.nodeIds.map((id) => ({ type: "organizational-units", id })),
    },
  },
});

/** Canonical `organization-nodes` resource (carries `kind`). */
const organizationNodeResource = (node: FixtureNode) => ({
  id: node.id,
  type: "organization-nodes",
  attributes: {
    name: node.name,
    kind: node.kind,
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

const applyResultResponse = (fx: OrgFixture) => ({
  data: {
    id: "apply-result-1",
    type: "organization-discovery-apply-results",
    attributes: {
      providers_created_count: fx.apply.providersCreatedCount,
      providers_linked_count: fx.apply.providersLinkedCount,
      providers_applied_count:
        fx.apply.providersCreatedCount + fx.apply.providersLinkedCount,
      // Canonical counter + deprecated alias.
      organization_nodes_created_count: fx.apply.nodesCreatedCount,
      organizational_units_created_count: fx.apply.nodesCreatedCount,
      account_provider_mappings: fx.apply.accountProviderMappings,
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
      organizational_units: {
        data: [],
        meta: { count: fx.apply.nodesCreatedCount },
      },
    },
  },
});

const taskResource = (id: string, state: string, result: unknown) => ({
  data: { id, type: "tasks", attributes: { state, result } },
});

/** Map a created-provider id back to its uid (AWS account id / GCP project). */
const uidForProviderId = (
  fx: OrgFixture,
  providerId: string,
): string | null => {
  const mapping = fx.apply.accountProviderMappings.find(
    (m) => m.provider_id === providerId,
  );
  if (mapping) return mapping.account_id;
  const provider = fx.providers.find((p) => p.id === providerId);
  return provider?.uid ?? null;
};

const CONNECTION_TASK_PREFIX = "conn-task-";
const DELETION_TASK_PREFIX = "del-task-";

export const handlersForOrganizations = (fx: OrgFixture) => {
  // Mutable working copy for resources created during the test lifecycle.
  const organizations = [...fx.organizations];
  const createdSecretIds = new Set(
    organizations.map((o) => o.secretId).filter((id): id is string => !!id),
  );
  let orgSeq = 0;
  let secretSeq = 0;

  const handlers = [
    // --- organizations CRUD + filters ------------------------------------
    http.get(`${API}/organizations`, ({ request }) => {
      const url = new URL(request.url);
      const externalId = url.searchParams.get("filter[external_id]");
      const orgType = url.searchParams.get("filter[org_type]");
      const data = organizations
        .filter((o) => (externalId ? o.externalId === externalId : true))
        .filter((o) => (orgType ? o.orgType === orgType : true))
        .map(organizationResource);
      return HttpResponse.json({ data, meta: { version: "v1" } });
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
        rootExternalId: null,
        providerIds: [],
        nodeIds: [],
        secretId: null,
      };
      organizations.push(created);
      return HttpResponse.json(
        { data: organizationResource(created) },
        { status: 201 },
      );
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
        return HttpResponse.json({ data: organizationResource(org) });
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
    http.get(`${API}/organization-nodes`, () =>
      HttpResponse.json({
        data: fx.nodes.map(organizationNodeResource),
        meta: { version: "v1" },
      }),
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
    http.post(`${API}/scans`, () =>
      HttpResponse.json(
        { data: { id: "scan-1", type: "scans", attributes: {} } },
        { status: 202 },
      ),
    ),
    http.post(`${API}/schedules`, () =>
      HttpResponse.json(
        { data: { id: "schedule-1", type: "schedules", attributes: {} } },
        { status: 202 },
      ),
    ),
    http.post(`${API}/schedules/bulk`, () => HttpResponse.json({ data: [] })),
  ];

  // Transition-window facade: the deprecated AWS-only routes are served
  // alongside the canonical ones until the Phase 1 tripwire flips them off.
  const deprecatedHandlers = [
    http.get(`${API}/organizational-units`, () =>
      HttpResponse.json({
        data: fx.nodes
          .filter((n) => n.kind === "organizational-unit")
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
