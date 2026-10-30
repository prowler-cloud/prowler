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
});
