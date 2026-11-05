import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { IssuesSummary } from "@/components/issues/issues-summary";
import { IssuesOverviewAttributes } from "@/types/issues";

const summary: IssuesOverviewAttributes = {
  issues: 13,
  findings: 1266,
  actionable: 4,
  not_exploitable_findings: 283,
  exploitable: 1,
  likely: 3,
  conditional: 5,
  not_exploitable: 2,
  unknown: 2,
};

describe("IssuesSummary", () => {
  it("states the reduction and the findings a control already covers", () => {
    // Given / When
    render(<IssuesSummary summary={summary} />);

    // Then
    expect(screen.getByRole("paragraph")).toHaveTextContent(
      "13 issues folded from 1,266 failed findings · 283 findings already covered by a control",
    );
    // The per-verdict links live on the verdict tabs, not here.
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });

  it("drops the coverage clause when no finding is covered", () => {
    // Given / When
    render(
      <IssuesSummary
        summary={{
          ...summary,
          issues: 1,
          findings: 1,
          not_exploitable_findings: 0,
        }}
      />,
    );

    // Then
    expect(screen.getByRole("paragraph")).toHaveTextContent(
      /^1 issue folded from 1 failed finding$/,
    );
  });
});
