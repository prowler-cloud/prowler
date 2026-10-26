import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { TooltipProvider } from "@/components/shadcn/tooltip";
import {
  type FindingComplianceFramework,
  WATCHLIST_SCOPE,
} from "@/types/compliance-watchlist";
import { IssueFinding } from "@/types/issues";

import { COMPLIANCE_LOOKUP_LIMIT, IssueCompliance } from "./issue-compliance";

const { getFrameworksMock } = vi.hoisted(() => ({
  getFrameworksMock: vi.fn(),
}));

vi.mock("@/actions/findings/finding-compliance-frameworks", () => ({
  getFindingComplianceFrameworks: getFrameworksMock,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn() }),
}));

const framework = (
  complianceId: string,
  name: string,
  inWatchlist = false,
): FindingComplianceFramework => ({
  id: complianceId,
  complianceId,
  providerType: "aws",
  scope: WATCHLIST_SCOPE.PROVIDER,
  framework: name,
  name,
  version: "",
  inWatchlist,
});

const finding = (id: string, checkId: string): IssueFinding => ({
  id,
  uid: id,
  checkId,
  checkTitle: checkId,
  severity: "high",
  triageStatus: "open",
  resourceUid: `r-${id}`,
});

const renderCompliance = (
  findings: IssueFinding[],
  scanId?: string,
  truncated?: boolean,
) =>
  render(
    <TooltipProvider>
      <IssueCompliance
        findings={findings}
        scanId={scanId}
        truncated={truncated}
      />
    </TooltipProvider>,
  );

const INCOMPLETE =
  "Not every finding could be checked, so this list may be incomplete.";

describe("IssueCompliance", () => {
  beforeEach(() => {
    getFrameworksMock.mockResolvedValue({ frameworks: [], unavailable: false });
  });

  it("looks up one finding per check, up to the limit", async () => {
    const findings = [
      finding("f1", "check-a"),
      finding("f2", "check-a"),
      ...Array.from({ length: COMPLIANCE_LOOKUP_LIMIT + 2 }, (_, i) =>
        finding(`g${i}`, `check-${i}`),
      ),
    ];
    renderCompliance(findings);

    expect(await screen.findByText(/map to a framework/)).toBeInTheDocument();
    expect(getFrameworksMock).toHaveBeenCalledTimes(COMPLIANCE_LOOKUP_LIMIT);
    expect(getFrameworksMock).toHaveBeenCalledWith("f2");
  });

  it("lists each framework once, the watchlist first, and opens it in the scan", async () => {
    // Given
    getFrameworksMock
      .mockResolvedValueOnce({
        frameworks: [
          framework("cis_aws", "CIS"),
          framework("soc2", "SOC2", true),
        ],
        unavailable: false,
      })
      .mockResolvedValueOnce({
        frameworks: [framework("cis_aws", "CIS")],
        unavailable: false,
      });
    const openMock = vi.spyOn(window, "open").mockImplementation(() => null);
    renderCompliance(
      [finding("f1", "check-a"), finding("f2", "check-b")],
      "scan-1",
    );

    // When
    const buttons = await screen.findAllByRole("button", { name: /^Open / });
    await userEvent.click(buttons[0]);

    // Then
    expect(buttons.map((b) => b.getAttribute("aria-label"))).toEqual([
      "Open SOC2 compliance details",
      "Open CIS compliance details",
    ]);
    expect(openMock).toHaveBeenCalledWith(
      "/compliance/SOC2?complianceId=soc2&scanId=scan-1",
      "_blank",
    );
  });

  it("says so when no framework could be loaded, and looks again on retry", async () => {
    // Given
    const user = userEvent.setup();
    getFrameworksMock.mockResolvedValueOnce({
      frameworks: [],
      unavailable: true,
    });
    renderCompliance([finding("f1", "check-a")]);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not load the frameworks for this issue.",
    );

    // When
    await user.click(screen.getByRole("button", { name: "Retry" }));

    // Then
    expect(
      await screen.findByText(/behind this issue map to a framework/),
    ).toBeInTheDocument();
    expect(getFrameworksMock).toHaveBeenCalledTimes(2);
  });

  it("does not claim no framework applies when one lookup failed", async () => {
    // Given
    getFrameworksMock
      .mockResolvedValueOnce({ frameworks: [], unavailable: false })
      .mockResolvedValueOnce({ frameworks: [], unavailable: true });

    // When
    renderCompliance([finding("f1", "check-a"), finding("f2", "check-b")]);

    // Then
    expect(await screen.findByText(INCOMPLETE)).toBeInTheDocument();
    expect(
      screen.queryByText(/behind this issue map to a framework/),
    ).not.toBeInTheDocument();
  });

  it("stops loading when a lookup is rejected", async () => {
    getFrameworksMock.mockRejectedValue(new Error("Network error"));
    renderCompliance([finding("f1", "check-a")]);

    expect(
      await screen.findByText("Could not load the frameworks for this issue."),
    ).toBeInTheDocument();
  });

  it("flags the list as incomplete when the findings are a capped preview", async () => {
    getFrameworksMock.mockResolvedValue({
      frameworks: [framework("cis_aws", "CIS")],
      unavailable: false,
    });
    renderCompliance([finding("f1", "check-a")], "scan-1", true);

    expect(
      await screen.findByRole("button", {
        name: "Open CIS compliance details",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(INCOMPLETE)).toBeInTheDocument();
  });
});
