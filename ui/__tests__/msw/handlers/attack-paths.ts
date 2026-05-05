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
];
