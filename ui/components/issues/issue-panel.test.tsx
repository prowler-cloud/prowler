import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useJiraDispatchStore } from "@/store/jira-dispatch/store";
import {
  ISSUE_FINDINGS_LIMIT,
  IssueAttributes,
  IssueFinding,
  IssueResource,
} from "@/types/issues";

import { IssuePanel } from "./issue-panel";

const { getIssue, getIssueFindings, getFindingById } = vi.hoisted(() => ({
  getIssue: vi.fn(),
  getIssueFindings: vi.fn(),
  getFindingById: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/issues",
  useRouter: () => ({ refresh: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock("@/actions/issues", () => ({
  getIssue,
  getIssueFindings,
  getIssueNotes: async () => [],
}));
vi.mock("@/actions/findings", () => ({ getFindingById }));
// The real helper sits behind the server-only `@/lib` barrel.
vi.mock("@/lib/finding-detail", () => ({
  expandFindingWithRelationships: (response?: { data?: unknown }) =>
    response?.data ?? null,
}));
vi.mock("@/components/issues/issue-compliance", () => ({
  IssueCompliance: ({ truncated }: { truncated: boolean }) =>
    truncated ? <p>Compliance from a capped preview</p> : null,
}));
vi.mock("@/components/findings/send-to-jira-modal", () => ({
  SendToJiraModal: () => null,
}));
vi.mock("@/components/findings/table", () => ({
  FindingDetailDrawer: ({ finding }: { finding: { id: string } }) => (
    <p>Detail of {finding.id}</p>
  ),
}));
vi.mock("@/components/issues/issue-graph", () => ({
  IssueGraph: ({
    resourceUids,
    onOpenFinding,
  }: {
    resourceUids: string[];
    onOpenFinding: (id: string) => void;
  }) => (
    <button type="button" onClick={() => onOpenFinding("graph-finding")}>
      Graph of {resourceUids.length} resources
    </button>
  ),
}));
// The real panel portals into the app shell's side panel, absent here.
vi.mock("@/components/side-panel/detail-side-panel", () => ({
  DetailSidePanel: ({
    title,
    children,
  }: {
    title: string;
    children: ReactNode;
  }) => <section aria-label={title}>{children}</section>,
}));

const resourceUids = Array.from({ length: 15 }, (_, i) => `resource-${i + 1}`);

const attributes = {
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

const issueWith = (
  overrides: Partial<IssueAttributes> = {},
  scanId: string | undefined = "scan-1",
): IssueResource => ({
  type: "issues",
  id: "issue-1",
  attributes: { ...attributes, ...overrides },
  relationships: {
    provider: { data: { type: "providers", id: "provider-1" } },
    ...(scanId && { scan: { data: { type: "scans", id: scanId } } }),
  },
});

const finding: IssueFinding = {
  id: "finding-1",
  uid: "f-1",
  checkId: "s3_bucket_public_access",
  checkTitle: "Bucket is public",
  severity: "critical",
  triageStatus: "risk_accepted",
  resourceUid: "bucket",
};

const detailWith = (resource_uids: string[], finding_uids: string[] = []) => ({
  data: { attributes: { resource_uids, finding_uids } },
});

const renderPanel = (
  issue: IssueResource = issueWith(),
  providerUid?: string,
) =>
  render(
    <IssuePanel
      issue={issue}
      providerUid={providerUid}
      open
      onOpenChange={vi.fn()}
    />,
  );

const openTab = (name: string) =>
  userEvent.click(screen.getByRole("tab", { name }));

describe("IssuePanel", () => {
  beforeEach(() => {
    getIssue.mockReset();
    getIssueFindings.mockReset().mockResolvedValue([]);
    getFindingById.mockReset();
    useJiraDispatchStore.getState().closeJiraDispatch();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("says where the path starts and shows each leg's evidence", async () => {
    // Given
    getIssue.mockResolvedValue(detailWith([]));

    // When
    renderPanel(
      issueWith({
        outcome: "data_exposure",
        attacker_start: "internet",
        legs: {
          reachability: {
            state: "yes",
            text: "Public access is enabled.",
            evidence: ["s3_public · arn:aws:s3:::bucket"],
          },
        } as IssueAttributes["legs"],
      }),
    );

    // Then
    expect(screen.getByText("Data exposure")).toBeInTheDocument();
    expect(screen.getByText("The internet")).toBeInTheDocument();
    // Shown inline so keyboard users can read it too.
    expect(
      screen.getByText(/Where the attacker has to be standing/),
    ).toBeInTheDocument();
    expect(
      within(
        screen.getByRole("list", { name: "Reachability evidence" }),
      ).getByText("s3_public · arn:aws:s3:::bucket"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Open the full path" }),
    ).not.toBeInTheDocument();
  });

  it("names the provider with its account uid, like the finding panel", () => {
    // Given
    getIssue.mockResolvedValue(detailWith([]));

    // When
    renderPanel(issueWith(), "123456789012");

    // Then
    expect(screen.getByText("Provider")).toBeInTheDocument();
    expect(screen.getByText("prod")).toBeInTheDocument();
    expect(screen.getByText("123456789012")).toBeInTheDocument();
    expect(screen.getByText("unmodelled")).toBeInTheDocument();
  });

  it("claims no outcome for an issue that is not one path", () => {
    getIssue.mockResolvedValue(detailWith([]));
    renderPanel();

    expect(screen.queryByText("Leads to")).not.toBeInTheDocument();
  });

  it("pages through every affected resource and links each to Resources", async () => {
    // Given
    getIssue.mockResolvedValue(detailWith(resourceUids));
    renderPanel();

    // When
    await openTab("Resources");

    // Then: the list leaves the uids out, so the panel fetches them
    expect(getIssue).toHaveBeenCalledWith("issue-1");
    expect(await screen.findByText("resource-1")).toBeInTheDocument();
    expect(screen.queryByText("resource-15")).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Open in Resources: resource-1" }),
    ).toHaveAttribute(
      "href",
      "/resources?filter%5Buid%5D=resource-1&filter%5Bprovider_id__in%5D=provider-1",
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Show more resources" }),
    );
    expect(screen.getByText("resource-15")).toBeInTheDocument();
  });

  it("says so when the resources cannot be loaded", async () => {
    getIssue.mockResolvedValue(undefined);
    renderPanel();

    await openTab("Resources");

    expect(
      await screen.findByText(/could not load the resources/i),
    ).toBeInTheDocument();
  });

  it("reports a failed findings request and retries using the issue scan", async () => {
    // Given
    getIssue.mockResolvedValue(detailWith(resourceUids, ["finding-uid"]));
    getIssueFindings
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce([finding]);
    renderPanel();

    // When
    await openTab("Findings");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not load the findings for this issue",
    );
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));

    // Then
    expect(
      await screen.findByRole("button", { name: "Bucket is public" }),
    ).toBeInTheDocument();
    expect(getIssueFindings).toHaveBeenLastCalledWith("scan-1", [
      "finding-uid",
    ]);
  });

  it("lists each folded finding once, with its own triage", async () => {
    // Given
    getIssue.mockResolvedValue(detailWith(["bucket"], ["f-1", "f-2"]));
    getIssueFindings.mockResolvedValue([
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
    renderPanel();

    // When
    await openTab("Findings");

    // Then
    const section = await screen.findByRole("region", { name: "Findings" });
    // One header row plus one row per finding.
    expect(within(section).getAllByRole("row")).toHaveLength(3);
    expect(within(section).getByText("Risk Accepted")).toBeInTheDocument();
    // Cards of one check tell their resources apart.
    expect(within(section).getByText("other-bucket")).toBeInTheDocument();
    expect(within(section).getByText("Showing 2 of 300")).toBeInTheDocument();
  });

  it("tells the compliance section when the findings preview was capped", async () => {
    // Given: one more finding than the preview loads
    getIssue.mockResolvedValue(
      detailWith(
        [],
        Array.from({ length: ISSUE_FINDINGS_LIMIT + 1 }, (_, i) => `uid-${i}`),
      ),
    );
    getIssueFindings.mockResolvedValue([finding]);
    renderPanel();

    // When
    await openTab("Findings");

    // Then
    expect(
      await screen.findByText("Compliance from a capped preview"),
    ).toBeInTheDocument();
  });

  it("opens a finding in place and goes back to the tab it came from", async () => {
    // Given
    getIssue.mockResolvedValue(detailWith(["bucket"], ["f-1"]));
    getIssueFindings.mockResolvedValue([finding]);
    getFindingById.mockResolvedValue({
      data: {
        id: "finding-1",
        attributes: { check_metadata: { checktitle: "Bucket is public" } },
        relationships: {},
      },
    });
    renderPanel();
    await openTab("Findings");

    // When
    await userEvent.click(
      await screen.findByRole("button", { name: "Bucket is public" }),
    );

    // Then: the finding replaces the tabs, with a way back
    expect(await screen.findByText("Detail of finding-1")).toBeInTheDocument();
    expect(getFindingById).toHaveBeenCalledWith(
      "finding-1",
      "resources,scan.provider",
    );
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();

    // When
    await userEvent.click(screen.getByText("Issue details"));

    // Then
    expect(screen.getByRole("tab", { name: "Findings" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });

  it("refreshes the findings behind the tabs when a finding closes", async () => {
    // Given: the finding is triaged while open in the panel
    getIssue.mockResolvedValue(detailWith(["bucket"], ["f-1"]));
    getIssueFindings
      .mockResolvedValueOnce([{ ...finding, triageStatus: "open" }])
      .mockResolvedValueOnce([{ ...finding, triageStatus: "risk_accepted" }]);
    getFindingById.mockResolvedValue({
      data: { id: "finding-1", attributes: {}, relationships: {} },
    });
    renderPanel();
    await openTab("Findings");
    await userEvent.click(
      await screen.findByRole("button", { name: "Bucket is public" }),
    );
    await screen.findByText("Detail of finding-1");

    // When
    await userEvent.click(screen.getByText("Issue details"));

    // Then: the row shows the new triage without dropping to a loading state
    expect(
      screen.getByRole("button", { name: "Bucket is public" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("Risk Accepted")).toBeInTheDocument();
    expect(screen.queryByText("Loading issue details…")).toBeNull();
  });

  it.each([
    {
      failure: "the findings request",
      fail: () => getIssueFindings.mockResolvedValueOnce(undefined),
      failing: getIssueFindings,
    },
    {
      failure: "the issue request",
      fail: () => getIssue.mockRejectedValueOnce(new Error("Offline")),
      failing: getIssue,
    },
  ])(
    "keeps the loaded rows when $failure fails on a background refresh",
    async ({ fail, failing }) => {
      // Given: the findings loaded, and a finding is open
      getIssue.mockResolvedValue(detailWith(["bucket"], ["f-1"]));
      getIssueFindings.mockResolvedValueOnce([finding]);
      getFindingById.mockResolvedValue({
        data: { id: "finding-1", attributes: {}, relationships: {} },
      });
      renderPanel();
      await openTab("Findings");
      await userEvent.click(
        await screen.findByRole("button", { name: "Bucket is public" }),
      );
      await screen.findByText("Detail of finding-1");
      fail();

      // When: closing it refreshes, and the refresh fails
      await userEvent.click(screen.getByText("Issue details"));

      // Then: once the failing refresh has settled, the rows stay
      await waitFor(() => expect(failing).toHaveBeenCalledTimes(2));
      await act(async () => {
        await failing.mock.results[1]?.value?.catch(() => undefined);
      });
      expect(
        screen.getByRole("button", { name: "Bucket is public" }),
      ).toBeInTheDocument();
      expect(screen.queryByRole("alert")).toBeNull();
    },
  );

  it("keeps the rows on screen while the background refresh is pending", async () => {
    // Given: the refresh after closing the finding never answers
    getIssue
      .mockResolvedValueOnce(detailWith(["bucket"], ["f-1"]))
      .mockReturnValueOnce(new Promise(() => {}));
    getIssueFindings.mockResolvedValueOnce([finding]);
    getFindingById.mockResolvedValue({
      data: { id: "finding-1", attributes: {}, relationships: {} },
    });
    renderPanel();
    await openTab("Findings");
    await userEvent.click(
      await screen.findByRole("button", { name: "Bucket is public" }),
    );
    await screen.findByText("Detail of finding-1");

    // When
    await userEvent.click(screen.getByText("Issue details"));
    await waitFor(() => expect(getIssue).toHaveBeenCalledTimes(2));

    // Then: the loaded rows stay, with no loading state in their place
    expect(
      screen.getByRole("button", { name: "Bucket is public" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Loading issue details…")).toBeNull();
  });

  it("applies refreshed resources even when the refreshed findings fail", async () => {
    // Given: the refresh brings a new resource but loses the findings
    getIssue
      .mockResolvedValueOnce(detailWith(["bucket"], ["f-1"]))
      .mockResolvedValueOnce(detailWith(["bucket", "new-bucket"], ["f-1"]));
    getIssueFindings
      .mockResolvedValueOnce([finding])
      .mockResolvedValueOnce(undefined);
    getFindingById.mockResolvedValue({
      data: { id: "finding-1", attributes: {}, relationships: {} },
    });
    renderPanel();
    await openTab("Findings");
    await userEvent.click(
      await screen.findByRole("button", { name: "Bucket is public" }),
    );
    await screen.findByText("Detail of finding-1");

    // When
    await userEvent.click(screen.getByText("Issue details"));
    await waitFor(() => expect(getIssueFindings).toHaveBeenCalledTimes(2));

    // Then: the findings stay, the resources follow the refresh
    expect(
      screen.getByRole("button", { name: "Bucket is public" }),
    ).toBeInTheDocument();
    await openTab("Resources");
    expect(await screen.findByText("new-bucket")).toBeInTheDocument();
  });

  it("opens a finding clicked on the attack path in place", async () => {
    // Given
    getIssue.mockResolvedValue(detailWith(["bucket"], ["f-1"]));
    getIssueFindings.mockResolvedValue([finding]);
    getFindingById.mockResolvedValue(undefined);
    renderPanel();
    await openTab("Attack path");

    // When
    await userEvent.click(
      await screen.findByRole("button", { name: "Graph of 1 resources" }),
    );

    // Then: a failed detail says so and can be retried
    expect(getFindingById).toHaveBeenCalledWith(
      "graph-finding",
      "resources,scan.provider",
    );
    expect(
      await screen.findByText("Could not load this finding."),
    ).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(getFindingById).toHaveBeenCalledTimes(2);
  });

  it("sends the unique findings to Jira from the actions menu", async () => {
    // Given: Prowler Cloud, where several findings can go in one dispatch
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    getIssue.mockResolvedValue(detailWith(["bucket"], ["f-1", "f-2"]));
    getIssueFindings.mockResolvedValue([
      finding,
      { ...finding, resourceUid: "other-bucket" },
      { ...finding, id: "finding-2", uid: "f-2" },
    ]);
    const view = renderPanel();

    // When
    await userEvent.click(
      await screen.findByRole("button", { name: "Issue actions" }),
    );
    await userEvent.click(
      await screen.findByRole("menuitem", { name: "Send 2 Findings to Jira" }),
    );
    view.unmount();

    // Then: the globally hosted modal survives the panel closing.
    expect(useJiraDispatchStore.getState().activePayload).toMatchObject({
      findingTitle: attributes.title,
      selection: {
        kind: "target-list",
        targetType: "finding_id",
        targetIds: ["finding-1", "finding-2"],
      },
    });
  });
});
