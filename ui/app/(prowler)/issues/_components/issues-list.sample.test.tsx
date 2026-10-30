import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { getIssues, getIssuesOverview } from "@/actions/issues";
import { SAMPLE_ISSUES } from "@/lib/sample-preview/sample-issues";
import { VERDICT } from "@/types/issues";

import { IssuesList } from "./issues-list";

vi.mock("@/actions/issues", () => ({
  getIssues: vi.fn(),
  getIssuesOverview: vi.fn(),
}));
// Modules that reach next-auth under jsdom; sample rows never open the panel.
vi.mock("@/components/issues/issue-panel", () => ({ IssuePanel: () => null }));
vi.mock("@/lib", () => ({ getPaginationInfo: vi.fn() }));
vi.mock("@/contexts", () => ({ useFilterTransitionOptional: () => null }));
vi.mock("next/navigation", () => ({
  usePathname: () => "/issues",
  useRouter: () => ({ push: vi.fn(), refresh: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

const [exploitable] = SAMPLE_ISSUES.filter(
  (issue) => issue.attributes.verdict === VERDICT.EXPLOITABLE,
);
const [notExploitable] = SAMPLE_ISSUES.filter(
  (issue) => issue.attributes.verdict === VERDICT.NOT_EXPLOITABLE,
);

describe("IssuesList sample preview", () => {
  it("renders the sample issues inert, filtered by verdict, without the API", async () => {
    // When
    render(
      await IssuesList({
        searchParams: { "filter[verdict]": VERDICT.EXPLOITABLE },
        sample: true,
      }),
    );

    // Then
    const title = screen.getByRole("button", {
      name: exploitable.attributes.title,
    });
    expect(title.closest("[inert]")).not.toBeNull();
    expect(
      screen.queryByText(notExploitable.attributes.title),
    ).not.toBeInTheDocument();
    expect(getIssues).not.toHaveBeenCalled();
    expect(getIssuesOverview).not.toHaveBeenCalled();
  });

  it("matches nothing for a scope the demo account is not in", async () => {
    render(
      await IssuesList({
        searchParams: { "filter[cloud]": "gcp" },
        sample: true,
      }),
    );

    expect(screen.getByText("No issues match this filter.")).toBeVisible();
    expect(
      screen.queryByText(exploitable.attributes.title),
    ).not.toBeInTheDocument();
    // The summary is scoped too, not just the rows.
    expect(screen.getByLabelText("All, 0 issues")).toBeInTheDocument();
  });

  it("matches every verdict of a verdict__in list", async () => {
    render(
      await IssuesList({
        searchParams: {
          "filter[verdict__in]": `${VERDICT.EXPLOITABLE},${VERDICT.NOT_EXPLOITABLE}`,
        },
        sample: true,
      }),
    );

    expect(
      screen.getByRole("button", { name: exploitable.attributes.title }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: notExploitable.attributes.title }),
    ).toBeInTheDocument();
  });

  it("reads a scalar verdict filter as one literal value", async () => {
    render(
      await IssuesList({
        searchParams: {
          "filter[verdict]": `${VERDICT.EXPLOITABLE},${VERDICT.NOT_EXPLOITABLE}`,
        },
        sample: true,
      }),
    );

    expect(screen.getByText("No issues match this filter.")).toBeVisible();
  });

  it("scopes the rows by severity like the API", async () => {
    const critical = SAMPLE_ISSUES.filter(
      (issue) => issue.attributes.severity === "critical",
    );
    const other = SAMPLE_ISSUES.find(
      (issue) => issue.attributes.severity !== "critical",
    );

    render(
      await IssuesList({
        searchParams: { "filter[severity]": "critical" },
        sample: true,
      }),
    );

    for (const issue of critical) {
      expect(
        screen.getByRole("button", { name: issue.attributes.title }),
      ).toBeInTheDocument();
    }
    expect(screen.queryByText(other!.attributes.title)).not.toBeInTheDocument();
  });
});
