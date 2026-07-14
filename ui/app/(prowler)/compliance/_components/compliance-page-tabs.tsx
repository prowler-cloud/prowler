"use client";

import { useRouter } from "next/navigation";
import { ReactNode } from "react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";
import { CloudFeatureBadge } from "@/components/shared/cloud-feature-badge";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { COMPLIANCE_TAB, type ComplianceTab } from "../_types";

interface CompliancePageTabsProps {
  activeTab: ComplianceTab;
  /** False in OSS: the Cross-Provider tab renders disabled with the
   *  "Available in Prowler Cloud" upsell badge. */
  crossProviderEnabled: boolean;
  perScanContent: ReactNode;
  crossProviderContent: ReactNode;
}

export const CompliancePageTabs = ({
  activeTab,
  crossProviderEnabled,
  perScanContent,
  crossProviderContent,
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

    // Per Scan renders without the query param so existing bookmarks and
    // shared links keep resolving to the default view.
    if (typedTab === COMPLIANCE_TAB.PER_SCAN) {
      router.push("/compliance");
    } else {
      router.push(`/compliance?tab=${typedTab}`);
    }
  };

  return (
    // Same layout spacing as the scans view tabs (scans-page-shell.tsx).
    <Tabs
      value={activeTab}
      onValueChange={handleTabChange}
      className="flex flex-col gap-[18px]"
    >
      <TabsList className="overflow-x-auto">
        <TabsTrigger value={COMPLIANCE_TAB.PER_SCAN}>Per Scan</TabsTrigger>
        <TabsTrigger
          value={COMPLIANCE_TAB.CROSS_PROVIDER}
          adornment={
            !crossProviderEnabled ? (
              <CloudFeatureBadge label="Cloud" />
            ) : undefined
          }
        >
          Cross-Provider
        </TabsTrigger>
      </TabsList>

      <TabsContent value={COMPLIANCE_TAB.PER_SCAN}>
        {perScanContent}
      </TabsContent>
      <TabsContent value={COMPLIANCE_TAB.CROSS_PROVIDER}>
        {crossProviderContent}
      </TabsContent>
    </Tabs>
  );
};
