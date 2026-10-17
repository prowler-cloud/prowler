import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store/cloud-upgrade/store";
import { PAID_PLAN_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { ThreatScoreBadge } from "./threatscore-badge";

const { downloadComplianceCsvMock, downloadComplianceReportPdfMock } =
  vi.hoisted(() => ({
    downloadComplianceCsvMock: vi.fn(),
    downloadComplianceReportPdfMock: vi.fn(),
  }));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/lib/helper", () => ({
  downloadComplianceCsv: downloadComplianceCsvMock,
  downloadComplianceReportPdf: downloadComplianceReportPdfMock,
}));

describe("ThreatScoreBadge", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "threatscore-badge.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses ActionDropdown for downloads instead of ComplianceDownloadContainer", () => {
    expect(source).toContain("ActionDropdown");
    expect(source).toContain("ActionDropdownItem");
    expect(source).toContain("downloadComplianceCsv");
    expect(source).toContain("downloadComplianceReportPdf");
    expect(source).not.toContain("ComplianceDownloadContainer");
  });

  describe("for subscription-only tenants", () => {
    beforeEach(() => {
      vi.clearAllMocks();
      useCloudUpgradeStore.getState().closeCloudUpgrade();
    });

    it.each([/Download CSV report/i, /Download PDF report/i])(
      "opens the paid plan upgrade instead of %s",
      async (label) => {
        // Given
        const user = userEvent.setup();
        render(
          <ThreatScoreBadge
            score={80}
            scanId="scan-1"
            provider="aws"
            subscriptionOnly
          />,
        );

        // When
        await user.click(
          screen.getByRole("button", {
            name: "Open compliance export actions",
          }),
        );
        await user.click(screen.getByRole("menuitem", { name: label }));

        // Then
        expect(downloadComplianceCsvMock).not.toHaveBeenCalled();
        expect(downloadComplianceReportPdfMock).not.toHaveBeenCalled();
        expect(useCloudUpgradeStore.getState().activeFeature).toBe(
          PAID_PLAN_UPGRADE_FEATURE.REPORT_DOWNLOAD,
        );
      },
    );
  });

  it("does not use Collapsible components", () => {
    expect(source).not.toContain("Collapsible");
    expect(source).not.toContain("CollapsibleTrigger");
    expect(source).not.toContain("CollapsibleContent");
  });
});
