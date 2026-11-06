import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

import { TriageStatusBadge } from "./triage-status-badge";

describe("TriageStatusBadge", () => {
  it("renders the labeled read-only status used in the finding drawer", () => {
    // Given / When
    render(<TriageStatusBadge status={FINDING_TRIAGE_STATUS.REMEDIATING} />);

    // Then
    expect(screen.getByText("Triage:")).toBeInTheDocument();
    expect(screen.getByText("Remediating")).toHaveClass("text-bg-data-info");
  });

  it("omits the label when the surrounding table already names the field", () => {
    // Given / When
    render(
      <TriageStatusBadge
        status={FINDING_TRIAGE_STATUS.RISK_ACCEPTED}
        showLabel={false}
      />,
    );

    // Then
    expect(screen.queryByText("Triage:")).not.toBeInTheDocument();
    expect(screen.getByText("Risk Accepted")).toBeInTheDocument();
  });
});
