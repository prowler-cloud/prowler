import { describe, expect, it } from "vitest";

import {
  ATTACK_PATH_QUERY_IDS,
  type AttackPathCartographySchemaAttributes,
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
  it("prepends a custom query with a schema documentation link", () => {
    // Given
    const schema: AttackPathCartographySchemaAttributes = {
      id: "aws-0.129.0",
      provider: "aws",
      cartography_version: "0.129.0",
      schema_url:
        "https://github.com/cartography-cncf/cartography/blob/0.129.0/docs/root/modules/aws/schema.md",
      raw_schema_url:
        "https://raw.githubusercontent.com/cartography-cncf/cartography/refs/tags/0.129.0/docs/root/modules/aws/schema.md",
    };

    // When
    const result = buildAttackPathQueries([presetQuery], schema);

    // Then
    expect(result[0]).toMatchObject({
      id: ATTACK_PATH_QUERY_IDS.CUSTOM,
      attributes: {
        name: "Custom openCypher query",
        short_description: "Write and run your own read-only query",
        documentation_link: {
          text: "Cartography schema used by Prowler for AWS graphs",
          link: schema.schema_url,
        },
      },
    });
    expect(result[1]).toEqual(presetQuery);
  });
});
