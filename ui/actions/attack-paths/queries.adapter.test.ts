import { beforeEach, describe, expect, it, vi } from "vitest";

import { DOCS_URLS } from "@/lib/external-urls";
import { isCloud } from "@/lib/shared/env";
import {
  ATTACK_PATH_QUERY_IDS,
  type AttackPathQuery,
  type AttackPathQueryParameter,
  type AttackPathQueryResultSummary,
} from "@/types/attack-paths";

import {
  adaptAttackPathQueriesResponse,
  buildAttackPathQueries,
} from "./queries.adapter";

vi.mock("@/lib/shared/env", () => ({ isCloud: vi.fn() }));

// Empty-query filtering only applies in Prowler Cloud; default the flag on for
// the filtering suite and cover the self-hosted (flag off) case explicitly.
beforeEach(() => {
  vi.mocked(isCloud).mockReturnValue(true);
});

const presetQuery: AttackPathQuery = {
  type: "attack-paths-scans",
  id: "preset-query",
  attributes: {
    name: "Preset Query",
    short_description: "Returns privileged attack paths",
    description: "Returns privileged attack paths.",
    provider: "aws",
    attribution: null,
    parameters: [],
  },
};

const makeQuery = (
  id: string,
  overrides: {
    result_summary?: AttackPathQueryResultSummary | null;
    parameters?: AttackPathQueryParameter[];
  } = {},
): AttackPathQuery => ({
  type: "attack-paths-scans",
  id,
  attributes: {
    name: id,
    short_description: "",
    description: "",
    provider: "aws",
    attribution: null,
    parameters: overrides.parameters ?? [],
    result_summary: overrides.result_summary,
  },
});

describe("adaptAttackPathQueriesResponse filtering", () => {
  it("keeps only queries with data, plus everything without a definite empty verdict", () => {
    const response = {
      data: [
        makeQuery("has-data", {
          result_summary: { status: "ok", has_data: true },
        }),
        makeQuery("empty", {
          result_summary: { status: "ok", has_data: false },
        }),
        makeQuery("errored", {
          result_summary: { status: "error", has_data: null },
        }),
        makeQuery("parameterized", {
          parameters: [
            {
              name: "ip",
              label: "IP",
              data_type: "string",
            } as AttackPathQueryParameter,
          ],
          result_summary: null,
        }),
        makeQuery("no-summary"), // scan predating the precompute step
      ],
    };

    const ids = adaptAttackPathQueriesResponse(response).data.map((q) => q.id);

    // the only one hidden is the parameterless query known to be empty
    expect(ids).toEqual(["has-data", "errored", "parameterized", "no-summary"]);
    expect(ids).not.toContain("empty");
  });

  it("returns an empty list for a missing response", () => {
    expect(adaptAttackPathQueriesResponse(undefined).data).toEqual([]);
  });

  it("updates the pagination count to the filtered length", () => {
    const response = {
      data: [
        makeQuery("a", { result_summary: { status: "ok", has_data: true } }),
        makeQuery("b", { result_summary: { status: "ok", has_data: false } }),
      ],
    };

    const { metadata } = adaptAttackPathQueriesResponse(response);
    expect(metadata?.pagination.count).toBe(1);
  });

  it("shows every query when not running in Cloud (feature flag off)", () => {
    vi.mocked(isCloud).mockReturnValue(false);
    const response = {
      data: [
        makeQuery("has-data", {
          result_summary: { status: "ok", has_data: true },
        }),
        makeQuery("empty", {
          result_summary: { status: "ok", has_data: false },
        }),
      ],
    };

    const ids = adaptAttackPathQueriesResponse(response).data.map((q) => q.id);
    // self-hosted keeps current behaviour: no filtering, even the empty one
    expect(ids).toEqual(["has-data", "empty"]);
  });
});

describe("buildAttackPathQueries", () => {
  it("prepends a custom query that links to the Prowler documentation", () => {
    // When
    const result = buildAttackPathQueries([presetQuery]);

    // Then
    expect(result[0]).toMatchObject({
      id: ATTACK_PATH_QUERY_IDS.CUSTOM,
      attributes: {
        name: "Custom openCypher query",
        short_description: "Write and run your own read-only query",
        documentation_link: {
          text: "Learn how to write custom openCypher queries",
          link: DOCS_URLS.ATTACK_PATHS_CUSTOM_QUERIES,
        },
      },
    });
    expect(result[1]).toEqual(presetQuery);
  });
});
