import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { COMPLIANCE_TAB } from "../_types";
import { CompliancePageTabs } from "./compliance-page-tabs";
import { getComplianceTab } from "./compliance-page-tabs.shared";

const { pushMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: pushMock,
  }),
}));

describe("getComplianceTab", () => {
  it("falls back to per-scan for missing or invalid values", () => {
    expect(getComplianceTab(undefined)).toBe(COMPLIANCE_TAB.PER_SCAN);
    expect(getComplianceTab(["cross-provider"])).toBe(COMPLIANCE_TAB.PER_SCAN);
    expect(getComplianceTab("bogus")).toBe(COMPLIANCE_TAB.PER_SCAN);
    expect(getComplianceTab("cross-provider")).toBe(
      COMPLIANCE_TAB.CROSS_PROVIDER,
    );
  });
});

describe("CompliancePageTabs", () => {
  beforeEach(() => {
    pushMock.mockClear();
  });

  afterEach(() => {
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  it("navigates with ?tab=cross-provider and back to the bare route", async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <CompliancePageTabs
        activeTab={COMPLIANCE_TAB.PER_SCAN}
        crossProviderEnabled
        perScanContent={<div>Per scan content</div>}
        crossProviderContent={<div>Cross provider content</div>}
      />,
    );

    await user.click(screen.getByRole("tab", { name: /multiple scans/i }));
    expect(pushMock).toHaveBeenCalledWith("/compliance?tab=cross-provider");

    rerender(
      <CompliancePageTabs
        activeTab={COMPLIANCE_TAB.CROSS_PROVIDER}
        crossProviderEnabled
        perScanContent={<div>Per scan content</div>}
        crossProviderContent={<div>Cross provider content</div>}
      />,
    );

    await user.click(screen.getByRole("tab", { name: /single scan/i }));
    expect(pushMock).toHaveBeenCalledWith("/compliance");
  });

  it("opens the cross-provider upgrade without changing tabs in Local Server", async () => {
    const user = userEvent.setup();
    render(
      <CompliancePageTabs
        activeTab={COMPLIANCE_TAB.PER_SCAN}
        crossProviderEnabled={false}
        perScanContent={<div>Per scan content</div>}
        crossProviderContent={null}
      />,
    );

    const crossProviderTab = screen.getByRole("tab", {
      name: /multiple scans/i,
    });
    await user.click(crossProviderTab);

    expect(crossProviderTab).not.toBeDisabled();
    expect(crossProviderTab).toHaveAttribute("aria-selected", "false");
    expect(screen.getByText("Cloud")).toBeVisible();
    expect(pushMock).not.toHaveBeenCalled();
    expect(useCloudUpgradeStore.getState().activeFeature).toBe(
      CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE,
    );
  });
});
