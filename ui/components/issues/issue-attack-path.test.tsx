import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { IssueAttributes } from "@/types/issues";

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn() }) }));
vi.mock("@/components/issues/issue-graph", () => ({
  IssueGraph: () => <p>graph</p>,
}));

import { IssueAttackPath } from "./issue-attack-path";

const issue = { legs: {} } as IssueAttributes;

describe("IssueAttackPath", () => {
  it("says there is nothing to draw, not a load error, without resources", () => {
    // Given: no resources, and findings that could not load without a scan
    render(
      <IssueAttackPath
        issue={issue}
        evidence={{
          status: "loaded",
          resources: [],
          findings: undefined,
          findingsTruncated: false,
        }}
        onRetry={vi.fn()}
        onOpenFinding={vi.fn()}
      />,
    );

    // Then
    expect(
      screen.getByText("This issue has no affected resources to draw."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });

  it("offers a retry when the findings for the drawn resources fail", async () => {
    // Given
    const onRetry = vi.fn();
    render(
      <IssueAttackPath
        issue={issue}
        evidence={{
          status: "loaded",
          resources: ["bucket"],
          findings: undefined,
          findingsTruncated: false,
        }}
        onRetry={onRetry}
        onOpenFinding={vi.fn()}
      />,
    );

    // When
    expect(
      screen.getByText("Could not load the attack path for this issue."),
    ).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));

    // Then
    expect(onRetry).toHaveBeenCalled();
  });
});
