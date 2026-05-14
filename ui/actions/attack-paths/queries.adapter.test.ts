import { describe, expect, it } from "vitest";

import { DOCS_URLS } from "@/lib/external-urls";
import {
  ATTACK_PATH_QUERY_IDS,
  type AttackPathQuery,
} from "@/types/attack-paths";

import { buildAttackPathQueries } from "./queries.adapter";

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
