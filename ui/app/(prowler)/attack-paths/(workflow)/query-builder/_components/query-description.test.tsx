import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  ATTACK_PATH_QUERY_IDS,
  type AttackPathQuery,
} from "@/types/attack-paths";

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

const builtInQuery: AttackPathQuery = {
  type: "attack-paths-scans",
  id: "aws-sts-privesc-assume-role",
  attributes: {
    name: "Role Assumption for Privilege Escalation (STS-001)",
    short_description: "Detect principals who can assume other IAM roles.",
    description:
      "Detect principals who can assume other IAM roles via sts:AssumeRole.",
    provider: "aws",
    attribution: null,
    parameters: [],
  },
};

describe("QueryDescription", () => {
  it("renders a Prowler Hub link for a built-in query", () => {
    // Given
    render(<QueryDescription query={builtInQuery} />);

    // When
    const link = screen.getByRole("link", { name: /view on prowler hub/i });

    // Then
    expect(link).toHaveAttribute(
      "href",
      "https://hub.prowler.com/attack-paths/aws-sts-privesc-assume-role",
    );
  });

  it("does not render a Prowler Hub link for the custom query", () => {
    // Given
    const query: AttackPathQuery = {
      ...customQuery,
      id: ATTACK_PATH_QUERY_IDS.CUSTOM,
    };

    // When
    render(<QueryDescription query={query} />);

    // Then
    expect(
      screen.queryByRole("link", { name: /view on prowler hub/i }),
    ).not.toBeInTheDocument();
  });

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

  it("does not render an unsafe documentation URL as a clickable link", () => {
    // Given
    const queryWithUnsafeLink: AttackPathQuery = {
      ...customQuery,
      attributes: {
        ...customQuery.attributes,
        documentation_link: {
          text: "Learn how to write custom openCypher queries",
          link: "javascript:alert('xss')",
        },
      },
    };

    // When
    render(<QueryDescription query={queryWithUnsafeLink} />);

    // Then
    expect(
      screen.queryByRole("link", {
        name: /learn how to write custom opencypher queries/i,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/learn how to write custom opencypher queries/i),
    ).toBeInTheDocument();
  });
});
