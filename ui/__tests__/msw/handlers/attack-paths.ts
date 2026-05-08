import { http, HttpResponse } from "msw";

import type { PageFixture } from "@/app/(prowler)/attack-paths/(workflow)/query-builder/attack-paths-page.fixtures";
import type {
  AttackPathQueriesResponse,
  AttackPathQuery,
  AttackPathQueryResult,
  AttackPathScan,
  AttackPathScansResponse,
  QueryResultAttributes,
} from "@/types/attack-paths";

const API = process.env.NEXT_PUBLIC_API_BASE_URL!;

type JsonApiErrorBody = {
  errors: Array<{ detail: string; status: string }>;
};

const toScansApiResponse = (
  scans: AttackPathScan[],
): AttackPathScansResponse => ({
  data: scans,
  links: {
    first: `${API}/attack-paths-scans?page=1`,
    last: `${API}/attack-paths-scans?page=1`,
    next: null,
    prev: null,
  },
});

const toQueriesApiResponse = (
  queries: AttackPathQuery[],
): AttackPathQueriesResponse => ({
  data: queries,
});

const toQueryResultApiResponse = (
  attrs: QueryResultAttributes,
  queryId: string,
): AttackPathQueryResult => ({
  data: {
    type: "attack-paths-query-run-requests",
    id: queryId,
    attributes: attrs,
  },
});

const toErrorBody = (detail: string, status: number): JsonApiErrorBody => ({
  errors: [{ detail, status: String(status) }],
});

const toFindingApiResponse = (fx: PageFixture, findingId: string) => {
  const findingNode = fx.queryResult?.nodes.find(
    (node) => node.id === findingId,
  );
  const resourceNode = fx.queryResult?.nodes.find((node) =>
    fx.queryResult?.relationships?.some(
      (rel) =>
        (rel.source === node.id && rel.target === findingId) ||
        (rel.target === node.id && rel.source === findingId),
    ),
  );
  const scan = fx.scans[0];
  const providerId = scan?.relationships?.provider?.data?.id ?? "provider-1";
  const resourceId = resourceNode?.id ?? "resource-1";

  return {
    data: {
      type: "findings",
      id: findingId,
      attributes: {
        uid: String(findingNode?.properties.id ?? findingId),
        delta: null,
        status: String(findingNode?.properties.status ?? "FAIL"),
        status_extended: "Status extended",
        severity: String(findingNode?.properties.severity ?? "critical"),
        check_id: "attack_path_check",
        muted: false,
        muted_reason: null,
        check_metadata: {
          risk: "High",
          notes: "",
          checkid: "attack_path_check",
          provider: "aws",
          severity: String(findingNode?.properties.severity ?? "critical"),
          checktype: [],
          dependson: [],
          relatedto: [],
          categories: ["security"],
          checktitle: String(
            findingNode?.properties.check_title ?? "Attack path finding",
          ),
          compliance: null,
          relatedurl: "",
          description: "Attack path finding description",
          remediation: {
            code: { cli: "", other: "", nativeiac: "", terraform: "" },
            recommendation: { url: "", text: "Fix the finding" },
          },
          additionalurls: [],
          servicename: String(resourceNode?.properties.service ?? "s3"),
          checkaliases: [],
          resourcetype: String(resourceNode?.labels[0] ?? "Resource"),
          subservicename: "",
          resourceidtemplate: "",
        },
        raw_result: null,
        inserted_at: "2026-04-21T10:00:00Z",
        updated_at: "2026-04-21T10:05:00Z",
        first_seen_at: null,
      },
      relationships: {
        resources: { data: [{ type: "resources", id: resourceId }] },
        scan: { data: { type: "scans", id: scan?.id ?? "scan-1" } },
      },
    },
    included: [
      {
        type: "resources",
        id: resourceId,
        attributes: {
          uid: String(resourceNode?.properties.arn ?? resourceId),
          name: String(resourceNode?.properties.name ?? resourceId),
          region: "us-east-1",
          service: String(resourceNode?.properties.service ?? "s3"),
          tags: {},
          type: String(resourceNode?.labels[0] ?? "Resource"),
          inserted_at: "2026-04-21T10:00:00Z",
          updated_at: "2026-04-21T10:05:00Z",
          details: null,
          partition: null,
        },
      },
      {
        type: "scans",
        id: scan?.id ?? "scan-1",
        attributes: {
          name: "Attack path scan",
          trigger: "manual",
          state: scan?.attributes.state ?? "completed",
          unique_resource_count: 1,
          progress: scan?.attributes.progress ?? 100,
          duration: scan?.attributes.duration ?? 0,
          started_at: scan?.attributes.started_at ?? "2026-04-21T10:00:00Z",
          inserted_at: scan?.attributes.inserted_at ?? "2026-04-21T10:00:00Z",
          completed_at: scan?.attributes.completed_at ?? "2026-04-21T10:05:00Z",
          scheduled_at: null,
          next_scan_at: "",
        },
        relationships: {
          provider: { data: { type: "providers", id: providerId } },
        },
      },
      {
        type: "providers",
        id: providerId,
        attributes: {
          provider: scan?.attributes.provider_type ?? "aws",
          uid: scan?.attributes.provider_uid ?? "123456789",
          alias: scan?.attributes.provider_alias ?? "Provider",
          connection: {
            connected: true,
            last_checked_at: "2026-04-21T10:00:00Z",
          },
          inserted_at: "2026-04-21T10:00:00Z",
          updated_at: "2026-04-21T10:05:00Z",
        },
      },
    ],
  };
};

export const handlersForFixture = (fx: PageFixture) => [
  http.get(`${API}/attack-paths-scans`, () =>
    HttpResponse.json<AttackPathScansResponse>(toScansApiResponse(fx.scans)),
  ),

  http.get<{ scanId: string }>(
    `${API}/attack-paths-scans/:scanId/queries`,
    () =>
      HttpResponse.json<AttackPathQueriesResponse>(
        toQueriesApiResponse(fx.queries),
      ),
  ),

  http.post<{ scanId: string }>(
    `${API}/attack-paths-scans/:scanId/queries/run`,
    () => {
      if (fx.queryError) {
        return HttpResponse.json<JsonApiErrorBody>(
          toErrorBody(fx.queryError.error, fx.queryError.status),
          { status: fx.queryError.status },
        );
      }
      if (!fx.queryResult) {
        return HttpResponse.json<JsonApiErrorBody>(
          toErrorBody("No data found", 404),
          { status: 404 },
        );
      }
      return HttpResponse.json<AttackPathQueryResult>(
        toQueryResultApiResponse(fx.queryResult, fx.queryId),
      );
    },
  ),

  http.post<{ scanId: string }>(
    `${API}/attack-paths-scans/:scanId/queries/custom`,
    () => {
      if (fx.queryError) {
        return HttpResponse.json<JsonApiErrorBody>(
          toErrorBody(fx.queryError.error, fx.queryError.status),
          { status: fx.queryError.status },
        );
      }
      if (!fx.queryResult) {
        return HttpResponse.json<JsonApiErrorBody>(
          toErrorBody("No data found", 404),
          { status: 404 },
        );
      }
      return HttpResponse.json<AttackPathQueryResult>(
        toQueryResultApiResponse(fx.queryResult, fx.queryId),
      );
    },
  ),

  http.get<{ findingId: string }>(`${API}/findings/:findingId`, ({ params }) =>
    HttpResponse.json(toFindingApiResponse(fx, params.findingId)),
  ),
];
