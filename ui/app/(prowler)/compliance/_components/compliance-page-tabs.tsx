"use client";

import { useRouter } from "next/navigation";
import { ReactNode } from "react";

import {
  Badge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn";
import { buildPerScanComplianceHref } from "@/lib/compliance/compliance-tab-url";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import { COMPLIANCE_TAB, type ComplianceTab } from "@/types/compliance";

interface CompliancePageTabsProps {
  activeTab: ComplianceTab;
  /** False in OSS: the Cross-Provider tab renders disabled with the
   *  "Available in Prowler Cloud" upsell badge. */
  crossProviderEnabled: boolean;
  perScanContent: ReactNode;
  crossProviderContent: ReactNode;
  /** Watchlist filter + editor. Sits on the tab bar rather than inside a tab
   *  because both of them read and write the same tenant-wide list. */
  watchlistControls?: ReactNode;
}

export const CompliancePageTabs = ({
  activeTab,
  crossProviderEnabled,
  perScanContent,
  crossProviderContent,
  watchlistControls,
}: CompliancePageTabsProps) => {
  const router = useRouter();
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  const handleTabChange = (tab: string) => {
    const typedTab = tab as ComplianceTab;

    if (typedTab === COMPLIANCE_TAB.CROSS_PROVIDER && !crossProviderEnabled) {
      openCloudUpgrade(CLOUD_UPGRADE_FEATURE.CROSS_PROVIDER_COMPLIANCE);
      return;
    }

    if (typedTab === activeTab) {
      return;
    }

    // Multiple Scans is the landing view, so it owns the bare route; Single
    // Scan pins `?tab=` to stay linkable.
    router.push(
      typedTab === COMPLIANCE_TAB.CROSS_PROVIDER
        ? "/compliance"
        : buildPerScanComplianceHref(),
    );
  };

  return (
    <Tabs value={activeTab} onValueChange={handleTabChange}>
      <div className="flex flex-col gap-[18px]">
        {/* Wraps below the tabs on narrow viewports instead of squeezing the
            triggers, which are the primary navigation of the page. */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div data-tour-id="view-compliance-tabs" className="overflow-x-auto">
            <TabsList>
              <TabsTrigger
                value={COMPLIANCE_TAB.CROSS_PROVIDER}
                adornment={
                  !crossProviderEnabled ? (
                    <Badge variant="cloud">Cloud</Badge>
                  ) : undefined
                }
              >
                Multiple Scans
              </TabsTrigger>
              <TabsTrigger value={COMPLIANCE_TAB.PER_SCAN}>
                Single Scan
              </TabsTrigger>
            </TabsList>
          </div>
          {watchlistControls}
        </div>

        <TabsContent value={COMPLIANCE_TAB.CROSS_PROVIDER}>
          {crossProviderContent}
        </TabsContent>
        <TabsContent value={COMPLIANCE_TAB.PER_SCAN}>
          {perScanContent}
        </TabsContent>
      </div>
    </Tabs>
  );
};
