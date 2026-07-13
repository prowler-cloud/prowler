import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

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

    await user.click(screen.getByRole("tab", { name: /cross-provider/i }));
    expect(pushMock).toHaveBeenCalledWith("/compliance?tab=cross-provider");

    rerender(
      <CompliancePageTabs
        activeTab={COMPLIANCE_TAB.CROSS_PROVIDER}
        crossProviderEnabled
        perScanContent={<div>Per scan content</div>}
        crossProviderContent={<div>Cross provider content</div>}
      />,
    );

    await user.click(screen.getByRole("tab", { name: /per scan/i }));
    expect(pushMock).toHaveBeenCalledWith("/compliance");
  });

  it("disables the cross-provider tab with the cloud upsell badge in OSS", () => {
    render(
      <CompliancePageTabs
        activeTab={COMPLIANCE_TAB.PER_SCAN}
        crossProviderEnabled={false}
        perScanContent={<div>Per scan content</div>}
        crossProviderContent={null}
      />,
    );

    const crossProviderTab = screen.getByRole("tab", {
      name: /cross-provider/i,
    });
    const tabLabel = screen.getByText("Cross-Provider", { exact: true });
    const cloudBadge = screen.getByText("Available in Prowler Cloud");

    expect(crossProviderTab).toBeDisabled();
    expect(crossProviderTab).not.toHaveClass("disabled:opacity-50");
    expect(tabLabel).toHaveClass("opacity-50");
    expect(cloudBadge.parentElement).toHaveClass("gap-2");
  });
});
