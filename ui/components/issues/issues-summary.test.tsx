import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { IssuesSummary } from "@/components/issues/issues-summary";
import { IssuesOverviewAttributes } from "@/types/issues";

const summary: IssuesOverviewAttributes = {
  issues: 13,
  findings: 41,
  actionable: 4,
  not_exploitable_findings: 1,
  exploitable: 1,
  likely: 3,
  conditional: 5,
  not_exploitable: 2,
  unknown: 2,
};

describe("IssuesSummary", () => {
  it("leads with the reduction and links every tile into the scoped list", () => {
    render(
      <IssuesSummary
        summary={summary}
        scope={{ "filter[provider_type__in]": "aws" }}
      />,
    );

    expect(
      screen.getByRole("link", { name: "41 Failed findings folded" }),
    ).toHaveAttribute("href", "/issues?filter%5Bprovider_type__in%5D=aws");
    expect(screen.getByRole("link", { name: "13 Issues" })).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "4 Exploitable or likely" }),
    ).toHaveAttribute(
      "href",
      "/issues?filter%5Bprovider_type__in%5D=aws&filter%5Bverdict__in%5D=exploitable%2Clikely",
    );
    expect(
      screen.getByRole("link", {
        name: "2 Not exploitable, 1 finding covered by a control",
      }),
    ).toHaveAttribute(
      "href",
      "/issues?filter%5Bprovider_type__in%5D=aws&filter%5Bverdict%5D=not_exploitable",
    );
    expect(screen.getByRole("link", { name: "2 Unknown" })).toHaveAttribute(
      "href",
      "/issues?filter%5Bprovider_type__in%5D=aws&filter%5Bverdict%5D=unknown",
    );
  });
});
