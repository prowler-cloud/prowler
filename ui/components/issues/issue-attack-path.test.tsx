import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { IssueAttributes } from "@/types/issues";

const { getIssue, getIssueFindings } = vi.hoisted(() => ({
  getIssue: vi.fn(),
  getIssueFindings: vi.fn(),
}));
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn() }) }));
vi.mock("@/actions/issues", () => ({ getIssue, getIssueFindings }));
vi.mock("@/components/issues/issue-graph", () => ({
  IssueGraph: () => <p>graph</p>,
}));

import { IssueAttackPath } from "./issue-attack-path";

const issue = { legs: {} } as IssueAttributes;

describe("IssueAttackPath", () => {
  it("says there is nothing to draw, not a load error, without resources", async () => {
    // Given: no resources, and findings that cannot load without a scan
    getIssue.mockResolvedValue({
      data: { attributes: { resource_uids: [], finding_uids: ["f1"] } },
    });

    // When
    render(<IssueAttackPath id="issue-1" issue={issue} />);

    // Then
    expect(
      await screen.findByText("This issue has no affected resources to draw."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });

  it("offers a retry when the findings for the drawn resources fail", async () => {
    // Given
    getIssue.mockResolvedValue({
      data: { attributes: { resource_uids: ["bucket"], finding_uids: ["f1"] } },
    });

    // When
    render(<IssueAttackPath id="issue-1" issue={issue} />);

    // Then
    expect(
      await screen.findByText("Could not load the attack path for this issue."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});
