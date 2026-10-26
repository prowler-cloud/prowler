import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { IssueDetail } from "@/components/issues/issue-detail";
import { useJiraDispatchStore } from "@/store/jira-dispatch/store";
import { ISSUE_FINDINGS_LIMIT, IssueAttributes } from "@/types/issues";

const { getIssueMock, getIssueFindingsMock } = vi.hoisted(() => ({
  getIssueMock: vi.fn(),
  getIssueFindingsMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn() }) }));

vi.mock("@/actions/issues", () => ({
  getIssue: getIssueMock,
  getIssueFindings: getIssueFindingsMock,
  getIssueNotes: async () => [],
}));

vi.mock("@/components/issues/issue-compliance", () => ({
  IssueCompliance: ({ truncated }: { truncated: boolean }) =>
    truncated ? <p>Compliance from a capped preview</p> : null,
}));
vi.mock("@/components/findings/send-to-jira-modal", () => ({
  SendToJiraModal: () => null,
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
  outcome: "",
  attacker_start: "",
  legs: {},
  fix: "Review these findings individually.",
  findings_count: 300,
  triage_status: "open",
  inserted_at: "",
  updated_at: "",
} as unknown as IssueAttributes;

describe("IssueDetail", () => {
  beforeEach(() => {
    getIssueMock.mockReset();
    getIssueFindingsMock.mockResolvedValue([]);
    useJiraDispatchStore.getState().closeJiraDispatch();
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

  it("says what a path buys the attacker and where it starts", async () => {
    getIssueMock.mockResolvedValue({
      data: { attributes: { resource_uids: [] } },
    });
    render(
      <IssueDetail
        id="issue-1"
        issue={{
          ...issue,
          pattern: "aws_public_bucket",
          outcome: "data_exposure",
          attacker_start: "internet",
        }}
      />,
    );

    expect(screen.getByText("Data exposure")).toBeInTheDocument();
    expect(screen.getByText("The internet")).toBeInTheDocument();
    // Shown inline so keyboard users can read it too.
    expect(
      screen.getByText(/Where the attacker has to be standing/),
    ).toBeInTheDocument();
  });

  it("tells the compliance section when the findings preview was capped", async () => {
    // Given - one more finding than the preview loads
    getIssueMock.mockResolvedValue({
      data: {
        attributes: {
          resource_uids: [],
          finding_uids: Array.from(
            { length: ISSUE_FINDINGS_LIMIT + 1 },
            (_, i) => `uid-${i}`,
          ),
        },
        relationships: { scan: { data: { type: "scans", id: "scan-1" } } },
      },
    });
    getIssueFindingsMock.mockResolvedValue([
      {
        id: "f1",
        checkId: "check-a",
        checkTitle: "Check A",
        severity: "high",
        resourceUid: "r1",
      },
    ]);

    // When
    render(<IssueDetail id="issue-1" issue={issue} />);

    // Then
    expect(
      await screen.findByText("Compliance from a capped preview"),
    ).toBeInTheDocument();
  });

  it("claims no outcome for an issue that is not one path", async () => {
    getIssueMock.mockResolvedValue({
      data: { attributes: { resource_uids: [] } },
    });
    render(<IssueDetail id="issue-1" issue={issue} />);

    expect(screen.queryByText("Outcome")).not.toBeInTheDocument();
  });

  it("links each affected resource to it on the Resources page", async () => {
    getIssueMock.mockResolvedValue({
      data: { attributes: { resource_uids: ["arn:aws:s3:::bucket"] } },
    });
    render(<IssueDetail id="issue-1" issue={issue} providerId="provider-1" />);

    expect(
      await screen.findByRole("link", {
        name: "Open in Resources: arn:aws:s3:::bucket",
      }),
    ).toHaveAttribute(
      "href",
      "/resources?filter%5Buid%5D=arn%3Aaws%3As3%3A%3A%3Abucket&filter%5Bprovider_id__in%5D=provider-1",
    );
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

  it("names the conditions that make the path, explained by each leg", async () => {
    getIssueMock.mockResolvedValue({
      data: { attributes: { resource_uids: [] } },
    });
    render(
      <IssueDetail
        id="issue-1"
        issue={{
          ...issue,
          outcome: "data_exposure",
          attacker_start: "internet",
          legs: {
            ...issue.legs,
            controls: {
              state: "no",
              text: "The public access block is off.",
              evidence: [],
            },
          },
        }}
      />,
    );

    const factors = screen.getByRole("list", { name: "Risk factors" });
    expect(factors).toHaveTextContent("Internet-reachable");
    expect(screen.getByText("No control blocking")).toHaveAttribute(
      "title",
      "The public access block is off.",
    );
  });

  it("lists each folded finding once, with its own triage and a link to it", async () => {
    getIssueMock.mockResolvedValue({
      data: {
        attributes: { resource_uids: ["bucket"], finding_uids: ["f-1", "f-2"] },
      },
    });
    const finding = {
      id: "finding-1",
      uid: "f-1",
      checkId: "s3_bucket_public_access",
      checkTitle: "Bucket is public",
      severity: "critical",
      triageStatus: "risk_accepted",
      resourceUid: "bucket",
    };
    getIssueFindingsMock.mockResolvedValue([
      finding,
      // The same finding on a second resource is still one finding.
      { ...finding, resourceUid: "other-bucket" },
      {
        ...finding,
        id: "finding-2",
        uid: "f-2",
        checkTitle: "Bucket has no logging",
        triageStatus: "open",
      },
    ]);
    render(<IssueDetail id="issue-1" issue={issue} scanId="scan-1" />);

    const section = await screen.findByRole("region", { name: "Findings" });
    const link = within(section).getByRole("link", {
      name: "Bucket is public",
    });
    const destination = new URL(link.getAttribute("href")!, "https://app.test");
    expect(Object.fromEntries(destination.searchParams)).toEqual({
      "filter[scan__in]": "scan-1",
      "filter[check_id__in]": "s3_bucket_public_access",
      "filter[resource_uid]": "other-bucket",
      "filter[muted]": "include",
      expandedCheckId: "s3_bucket_public_access",
    });
    expect(within(section).getAllByRole("listitem")).toHaveLength(2);
    expect(within(section).getByText("Risk Accepted")).toBeInTheDocument();
    expect(within(section).getByText("Showing 2 of 300.")).toBeInTheDocument();
  });

  it("opens the global Jira flow with unique finding IDs", async () => {
    // Given
    const user = userEvent.setup();
    getIssueMock.mockResolvedValue({
      data: {
        attributes: { resource_uids: ["bucket"], finding_uids: ["f-1"] },
      },
    });
    const finding = {
      id: "finding-1",
      uid: "f-1",
      checkId: "s3_public",
      checkTitle: "Bucket is public",
      severity: "critical",
      triageStatus: "open",
      resourceUid: "bucket",
    };
    getIssueFindingsMock.mockResolvedValue([
      finding,
      { ...finding, resourceUid: "other-bucket" },
      { ...finding, id: "finding-2", uid: "f-2" },
    ]);
    const view = render(
      <IssueDetail id="issue-1" issue={issue} scanId="scan-1" />,
    );

    // When
    await user.click(
      await screen.findByRole("button", { name: "Send to Jira" }),
    );
    view.unmount();

    // Then: the globally hosted modal survives the detail closing.
    expect(useJiraDispatchStore.getState().activePayload).toMatchObject({
      findingTitle: issue.title,
      selection: {
        kind: "target-list",
        targetType: "finding_id",
        targetIds: ["finding-1", "finding-2"],
      },
    });
  });
});
