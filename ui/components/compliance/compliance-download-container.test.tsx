import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { downloadComplianceCsvMock, downloadCompliancePdfMock } = vi.hoisted(
  () => ({
    downloadComplianceCsvMock: vi.fn(),
    downloadCompliancePdfMock: vi.fn(),
  }),
);

vi.mock("@/lib/helper", () => ({
  downloadComplianceCsv: downloadComplianceCsvMock,
  downloadCompliancePdf: downloadCompliancePdfMock,
}));

vi.mock("@/components/ui", () => ({
  toast: {},
}));

import { ComplianceDownloadContainer } from "./compliance-download-container";

describe("ComplianceDownloadContainer", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "compliance-download-container.tsx");
  const source = readFileSync(filePath, "utf8");

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("uses the shared action dropdown for the card actions mode", () => {
    expect(source).toContain("ActionDropdown");
    expect(source).not.toContain("@heroui/button");
  });

  it("should expose an accessible actions menu trigger", () => {
    render(
      <ComplianceDownloadContainer
        compact
        presentation="dropdown"
        scanId="scan-1"
        complianceId="compliance-1"
        reportType="threatscore"
      />,
    );

    expect(
      screen.getByRole("button", { name: "Open compliance export actions" }),
    ).toBeInTheDocument();
  });

  it("should support fixed icon-sized dropdown trigger in column mode", () => {
    render(
      <ComplianceDownloadContainer
        compact
        presentation="dropdown"
        orientation="column"
        buttonWidth="icon"
        scanId="scan-1"
        complianceId="compliance-1"
        reportType="threatscore"
      />,
    );

    const trigger = screen.getByRole("button", {
      name: "Open compliance export actions",
    });
    expect(trigger.className).toContain("border-text-neutral-secondary");
  });

  it("should open export actions from the compact trigger", async () => {
    const user = userEvent.setup();

    render(
      <ComplianceDownloadContainer
        compact
        presentation="dropdown"
        scanId="scan-1"
        complianceId="compliance-1"
        reportType="threatscore"
      />,
    );

    await user.click(
      screen.getByRole("button", { name: "Open compliance export actions" }),
    );

    expect(screen.getByText("Download CSV report")).toBeInTheDocument();
    expect(screen.getByText("Download PDF report")).toBeInTheDocument();
  });

  it("should trigger both downloads from the actions menu", async () => {
    const user = userEvent.setup();

    render(
      <ComplianceDownloadContainer
        compact
        presentation="dropdown"
        scanId="scan-1"
        complianceId="compliance-1"
        reportType="threatscore"
      />,
    );

    await user.click(
      screen.getByRole("button", { name: "Open compliance export actions" }),
    );
    await user.click(
      screen.getByRole("menuitem", { name: /Download CSV report/i }),
    );
    await user.click(
      screen.getByRole("button", { name: "Open compliance export actions" }),
    );
    await user.click(
      screen.getByRole("menuitem", { name: /Download PDF report/i }),
    );

    expect(downloadComplianceCsvMock).toHaveBeenCalledWith(
      "scan-1",
      "compliance-1",
      {},
    );
    expect(downloadCompliancePdfMock).toHaveBeenCalledWith(
      "scan-1",
      "threatscore",
      {},
    );
  });
});
