import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import type { IssueResponse } from "@/types/issues";

import { IssuesTable } from "./issues-table";

const { push, getIssue } = vi.hoisted(() => ({
  push: vi.fn(),
  getIssue: vi.fn(),
}));
vi.mock("next/navigation", () => ({
  usePathname: () => "/issues",
  useRouter: () => ({ push, refresh: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock("@/lib", () => ({ getPaginationInfo: vi.fn() }));
vi.mock("@/contexts", () => ({ useFilterTransitionOptional: () => null }));
vi.mock("@/actions/issues", () => ({
  getIssue,
  getIssueFindings: async () => [],
  getIssueNotes: async () => [],
}));
vi.mock("@/actions/findings", () => ({ getFindingById: vi.fn() }));
vi.mock("@/components/findings/table", () => ({
  FindingDetailDrawer: () => null,
}));
vi.mock("@/components/issues/issue-graph", () => ({
  IssueGraph: ({ resourceUids }: { resourceUids: string[] }) => (
    <p>Graph of {resourceUids.join(", ")}</p>
  ),
}));
// The real panel portals into the app shell's side panel, absent here.
vi.mock("@/components/side-panel/detail-side-panel", () => ({
  DetailSidePanel: ({
    open,
    onOpenChange,
    title,
    children,
  }: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    title: string;
    children: ReactNode;
  }) =>
    open ? (
      <section aria-label={title}>
        <button type="button" onClick={() => onOpenChange(false)}>
          Close panel
        </button>
        {children}
      </section>
    ) : null,
}));

const issue: IssueResponse["data"][number] = {
  type: "issues",
  id: "issue-1",
  attributes: {
    pattern: "aws_public_bucket",
    cloud: "aws",
    account: "prod",
    title: "Public bucket",
    verdict: "likely",
    severity: "high",
    outcome: "data_exposure",
    attacker_start: "internet",
    findings_count: 3,
    triage_status: "open",
    notes_count: 0,
    fix: "Restrict access",
    inserted_at: "",
    updated_at: "",
    legs: {
      reachability: { state: "yes", text: "Public", evidence: [] },
      access: { state: "partial", text: "Some controls", evidence: [] },
      target: { state: "unknown", text: "Not verified", evidence: [] },
      controls: { state: "no", text: "Block Public Access off", evidence: [] },
      verification: { state: "yes", text: "Logging on", evidence: [] },
    },
  },
  relationships: { scan: { data: { type: "scans", id: "scan-1" } } },
};

describe("IssuesTable", () => {
  it("sorts findings and verdicts through the URL", async () => {
    // Given
    const user = userEvent.setup();
    render(<IssuesTable issues={[issue]} />);
    // When
    await user.click(screen.getByRole("button", { name: "Findings" }));
    // Then
    expect(push).toHaveBeenLastCalledWith("/issues?sort=findings_count", {
      scroll: false,
    });
    // When
    await user.click(screen.getByRole("button", { name: "Verdict" }));
    // Then
    expect(push).toHaveBeenLastCalledWith("/issues?sort=verdict_rank", {
      scroll: false,
    });
  });

  it("says where the path starts, where it leads and why, in the row", () => {
    // Given / When
    render(<IssuesTable issues={[issue]} />);
    const row = screen.getByRole("row", { name: /Public bucket/ });

    // Then
    expect(
      within(row).getByText("The internet → Data exposure · aws_public_bucket"),
    ).toBeInTheDocument();
    expect(within(row).getByText("High")).toBeInTheDocument();
    const legs = within(row).getByRole("list", { name: "Attack path legs" });
    expect(
      within(legs)
        .getAllByRole("listitem")
        .map((item) => item.getAttribute("aria-label")),
    ).toEqual([
      "Reachability: Yes",
      "Access: Partly",
      "Target: Unknown",
      "Controls: No",
      "Verification: Yes",
    ]);
  });

  it("opens the issue in the side panel and closes it", async () => {
    // Given
    const user = userEvent.setup();
    getIssue.mockResolvedValue({
      data: {
        ...issue,
        attributes: { ...issue.attributes, resource_uids: ["bucket"] },
      },
    });
    render(<IssuesTable issues={[issue]} />);

    // When
    await user.click(screen.getByRole("button", { name: "Public bucket" }));

    // Then: the assessment tab leads, and nothing sends the user elsewhere
    const panel = screen.getByRole("region", { name: "Public bucket" });
    expect(
      within(panel).getByRole("tab", { name: "Exploitability" }),
    ).toHaveAttribute("aria-selected", "true");
    expect(within(panel).getByText("Block Public Access off")).toBeVisible();
    expect(
      within(panel).queryByRole("link", { name: "Open the full path" }),
    ).not.toBeInTheDocument();

    // When
    await user.click(within(panel).getByRole("tab", { name: "Remediation" }));

    // Then
    expect(within(panel).getByText("Restrict access")).toBeVisible();

    // When: the scan's failed findings sit in the actions menu
    await user.click(
      within(panel).getByRole("button", { name: "Issue actions" }),
    );
    await user.click(
      await screen.findByRole("menuitem", {
        name: "Open this scan's failed findings",
      }),
    );

    // Then
    expect(push).toHaveBeenLastCalledWith(
      "/findings?filter%5Bscan__in%5D=scan-1&filter%5Bstatus__in%5D=FAIL",
    );

    // When
    await user.click(within(panel).getByRole("tab", { name: "Attack path" }));

    // Then
    expect(
      await within(panel).findByText("Graph of bucket"),
    ).toBeInTheDocument();
    expect(getIssue).toHaveBeenCalledWith("issue-1");

    // When
    await user.click(within(panel).getByRole("tab", { name: "Triage" }));

    // Then
    expect(
      within(panel).getByRole("textbox", { name: "Triage note" }),
    ).toBeInTheDocument();

    // When
    await user.click(screen.getByRole("button", { name: "Close panel" }));

    // Then
    expect(
      screen.queryByRole("region", { name: "Public bucket" }),
    ).not.toBeInTheDocument();
  });
});
