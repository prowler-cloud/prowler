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
      text: "Learn how to write custom openCypher queries",
      link: "https://example.com/docs",
    },
    parameters: [],
  },
};

describe("QueryDescription", () => {
  it("renders the documentation link inside an info alert", () => {
    // Given
    render(<QueryDescription query={customQuery} />);

    // When
    const alert = screen.getByRole("alert");
    const link = screen.getByRole("link", {
      name: /learn how to write custom opencypher queries/i,
    });

    // Then
    expect(alert).toBeInTheDocument();
    expect(link).toHaveAttribute("href", "https://example.com/docs");
  });

  it("does not render unsafe documentation or attribution URLs as clickable links", () => {
    // Given
    const queryWithUnsafeLinks: AttackPathQuery = {
      ...customQuery,
      attributes: {
        ...customQuery.attributes,
        documentation_link: {
          text: "Learn how to write custom openCypher queries",
          link: "javascript:alert('xss')",
        },
        attribution: {
          text: "Unsafe source",
          link: "javascript:alert('xss')",
        },
      },
    };

    // When
    render(<QueryDescription query={queryWithUnsafeLinks} />);

    // Then
    expect(
      screen.queryByRole("link", {
        name: /learn how to write custom opencypher queries/i,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /unsafe source/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/learn how to write custom opencypher queries/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/unsafe source/i)).toBeInTheDocument();
  });
});
