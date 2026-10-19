import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { IssueDetail } from "@/components/issues/issue-detail";
import { IssueAttributes } from "@/types/issues";

const { getIssueMock, getIssueFindingsMock } = vi.hoisted(() => ({
  getIssueMock: vi.fn(),
  getIssueFindingsMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn() }) }));

vi.mock("@/actions/issues", () => ({
  getIssue: getIssueMock,
  getIssueFindings: getIssueFindingsMock,
}));

vi.mock("@/components/issues/issue-graph", () => ({
  IssueGraph: ({ resourceUids }: { resourceUids: string[] }) => (
    <div data-testid="issue-graph">{resourceUids.length} resources</div>
  ),
}));

const resourceUids = Array.from({ length: 15 }, (_, i) => `resource-${i + 1}`);

const issue = {
  pattern: "unmodelled",
  cloud: "aws",
  account: "prod",
  title: "Findings no attack path models yet (300)",
  verdict: "unknown",
  severity: "high",
  legs: {},
  fix: "Review these findings individually.",
  findings_count: 300,
  inserted_at: "",
  updated_at: "",
} as unknown as IssueAttributes;

describe("IssueDetail", () => {
  beforeEach(() => {
    getIssueMock.mockReset();
    getIssueFindingsMock.mockResolvedValue([]);
  });

  it("links to the issue's scan findings and reveals every folded resource", async () => {
    getIssueMock.mockResolvedValue({
      data: { attributes: { resource_uids: resourceUids } },
    });
    const user = userEvent.setup();
    render(<IssueDetail id="issue-1" issue={issue} scanId="scan-1" />);

    expect(
      screen.getByRole("link", { name: /failed findings/i }),
    ).toHaveAttribute(
      "href",
      "/findings?filter%5Bscan__in%5D=scan-1&filter%5Bstatus__in%5D=FAIL",
    );

    // The list leaves the uids out; the detail fetches them when it opens.
    expect(getIssueMock).toHaveBeenCalledWith("issue-1");
    expect(await screen.findByText("resource-1")).toBeInTheDocument();
    expect(screen.queryByText("resource-15")).not.toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: "Show more resources" }),
    );
    expect(screen.getByText("resource-15")).toBeInTheDocument();
    expect(screen.getByTestId("issue-graph")).toHaveTextContent("15 resources");
  });

  it("says so when the resources cannot be loaded", async () => {
    getIssueMock.mockResolvedValue(undefined);
    render(<IssueDetail id="issue-1" issue={issue} />);

    expect(
      await screen.findByText(/could not load the resources/i),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("issue-graph")).not.toBeInTheDocument();
  });

  it("reports a failed findings request and retries using the issue scan", async () => {
    // Given
    getIssueMock.mockResolvedValue({
      data: {
        attributes: {
          resource_uids: resourceUids,
          finding_uids: ["finding-uid"],
        },
      },
    });
    getIssueFindingsMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce([]);
    render(<IssueDetail id="issue-1" issue={issue} scanId="scan-1" />);

    // When
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not load the findings for this issue",
    );
    expect(screen.queryByTestId("issue-graph")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));

    // Then
    expect(await screen.findByTestId("issue-graph")).toBeInTheDocument();
    expect(getIssueFindingsMock).toHaveBeenLastCalledWith("scan-1", [
      "finding-uid",
    ]);
  });
});
