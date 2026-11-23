import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getIssues, getIssuesOverview } from "@/actions/issues";

import { IssuesList } from "./issues-list";

vi.mock("@/actions/issues", () => ({
  getIssues: vi.fn(),
  getIssuesOverview: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

vi.mock("@/components/issues/verdict-filter", () => ({
  VerdictFilter: () => null,
}));

vi.mock("@/components/issues/issues-table", () => ({
  IssuesTable: () => null,
}));

describe("IssuesList", () => {
  beforeEach(() => {
    vi.mocked(getIssuesOverview).mockResolvedValue({
      data: {
        type: "issues-overview",
        attributes: {
          exploitable: 0,
          likely: 0,
          conditional: 0,
          not_exploitable: 0,
          unknown: 0,
          issues: 0,
          findings: 0,
          actionable: 0,
          not_exploitable_findings: 0,
        },
      },
    });
  });

  it.each([
    ["a 4xx", { error: "Forbidden", status: 403 }],
    ["a network failure", undefined],
  ])("shows a load error, not an empty state, on %s", async (_, response) => {
    vi.mocked(getIssues).mockResolvedValue(response as never);

    render(await IssuesList({ searchParams: {} }));

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Failed to load issues.",
    );
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    expect(screen.queryByText(/No issues match/)).not.toBeInTheDocument();
  });

  it("shows the empty state for a successful empty list", async () => {
    vi.mocked(getIssues).mockResolvedValue({ data: [] } as never);

    render(await IssuesList({ searchParams: {} }));

    expect(
      screen.getByText("No issues match this filter."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  it("reports a summary failure without replacing it with zero counts", async () => {
    // Given
    vi.mocked(getIssuesOverview).mockResolvedValue(undefined);
    vi.mocked(getIssues).mockResolvedValue({ data: [] });
    // When
    render(await IssuesList({ searchParams: {} }));
    // Then
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Failed to load issue summary.",
    );
    expect(
      screen.getByText("No issues match this filter."),
    ).toBeInTheDocument();
  });

  it("forwards combined verdict filters only to the list", async () => {
    vi.mocked(getIssues).mockResolvedValue({ data: [] });
    await IssuesList({
      searchParams: {
        "filter[verdict__in]": "exploitable,likely",
        "filter[provider_id__in]": "provider-1",
      },
    });
    expect(getIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({
        filters: {
          "filter[verdict__in]": "exploitable,likely",
          "filter[provider_id__in]": "provider-1",
        },
      }),
    );
    expect(getIssuesOverview).toHaveBeenLastCalledWith({
      filters: { "filter[provider_id__in]": "provider-1" },
    });
  });
});
