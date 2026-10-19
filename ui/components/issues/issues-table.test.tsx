import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

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
vi.mock("@/actions/issues", () => ({ getIssue }));
vi.mock("@/components/issues/issue-graph", () => ({ IssueGraph: () => null }));

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
    findings_count: 3,
    fix: "Restrict access",
    inserted_at: "",
    updated_at: "",
    legs: Object.fromEntries(
      ["reachability", "access", "target", "controls", "verification"].map(
        (name) => [
          name,
          { state: "unknown", text: "Not observed", evidence: [] },
        ],
      ),
    ) as unknown as IssueResponse["data"][number]["attributes"]["legs"],
  },
};

describe("IssuesTable", () => {
  beforeEach(() => {
    getIssue.mockResolvedValue({ data: { attributes: { resource_uids: [] } } });
  });

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
  it("opens and closes the detail with the keyboard", async () => {
    // Given
    const user = userEvent.setup();
    render(<IssuesTable issues={[issue]} />);
    // When
    const toggle = screen.getByRole("button", { name: "Expand Public bucket" });
    toggle.focus();
    await user.keyboard("{Enter}");
    // Then
    expect(
      screen.getByRole("button", { name: "Collapse Public bucket" }),
    ).toHaveAttribute("aria-expanded", "true");
    expect(await screen.findByText("Restrict access")).toBeInTheDocument();
    // When
    await user.keyboard(" ");
    // Then
    expect(screen.queryByText("Restrict access")).not.toBeInTheDocument();
  });
});
