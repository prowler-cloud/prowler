import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { AttackPathQuery } from "@/types/attack-paths";

import { QueryDescription } from "./query-description";

const customQuery: AttackPathQuery = {
  type: "attack-paths-scans",
  id: "custom-query",
  attributes: {
    name: "Custom openCypher query",
    short_description: "Write your own query",
    description:
      "Run a read-only openCypher query against the selected Attack Paths scan.",
    provider: "aws",
    attribution: null,
    documentation_link: {
      text: "Cartography schema used by Prowler for AWS graphs",
      link: "https://example.com/schema",
    },
    parameters: [],
  },
};

describe("QueryDescription", () => {
  it("renders the schema documentation link when the selected query provides one", () => {
    // Given
    render(<QueryDescription query={customQuery} />);

    // When
    const link = screen.getByRole("link", {
      name: /cartography schema used by prowler for aws graphs/i,
    });

    // Then
    expect(link).toHaveAttribute("href", "https://example.com/schema");
  });
});
