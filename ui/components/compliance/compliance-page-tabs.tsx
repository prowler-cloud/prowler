"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { ReactNode } from "react";

import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/shadcn";
import { CloudFeatureBadgeLink } from "@/components/shared/cloud-feature-badge";

import {
  COMPLIANCE_PAGE_TAB,
  type CompliancePageTab,
} from "./compliance-page-tabs.shared";

interface CompliancePageTabsProps {
  activeTab: CompliancePageTab;
  perScanContent: ReactNode;
  crossProviderContent: ReactNode;
  /** Cross-Provider is a Prowler Cloud-only feature (the OSS API has no
   *  ``cross-provider-compliance-overviews`` endpoint). In OSS the tab is
   *  rendered disabled with the "Available in Prowler Cloud" upsell badge,
   *  mirroring how the sidebar gates Alerts/Scan Configuration. */
  crossProviderEnabled?: boolean;
}

/**
 * Top-level tab switcher for the compliance index page.
 *
 * URL-based state: the active tab is reflected in ``?tab=<id>``. ``per-scan``
 * is the default and renders without the query param so existing bookmarks
 * keep working. The ``cross-provider`` tab uses ``?tab=cross-provider``.
 *
 * Filter params unrelated to a specific tab (e.g. ``filter[region__in]``)
 * survive tab switches; the per-scan-only ``scanId`` and the
 * cross-provider-only ``filter[provider_type__in]`` are pruned when leaving
 * their tab so the URL stays in sync with what the user can see.
 */
export const CompliancePageTabs = ({
  activeTab,
  perScanContent,
  crossProviderContent,
  crossProviderEnabled = true,
}: CompliancePageTabsProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const handleTabChange = (next: string) => {
    const target = next as CompliancePageTab;
    if (target === activeTab) return;
    // Cross-Provider is Cloud-only; ignore any attempt to switch to it in OSS.
    if (
      target === COMPLIANCE_PAGE_TAB.CROSS_PROVIDER &&
      !crossProviderEnabled
    ) {
      return;
    }

    const params = new URLSearchParams(searchParams.toString());

    if (target === COMPLIANCE_PAGE_TAB.PER_SCAN) {
      params.delete("tab");
      // provider_type__in only applies to cross-provider; drop it.
      params.delete("filter[provider_type__in]");
    } else {
      params.set("tab", target);
      // scanId is per-scan only; drop it when entering cross-provider.
      params.delete("scanId");
    }

    const query = params.toString();
    router.push(query ? `/compliance?${query}` : "/compliance");
  };

  return (
    <Tabs
      value={activeTab}
      onValueChange={handleTabChange}
      className="flex w-full flex-col gap-6"
    >
      <TooltipProvider delayDuration={200}>
        <TabsList>
          <Tooltip>
            <TooltipTrigger asChild>
              <TabsTrigger value={COMPLIANCE_PAGE_TAB.PER_SCAN}>
                Per Scan
              </TabsTrigger>
            </TooltipTrigger>
            <TooltipContent side="bottom" sideOffset={6}>
              Detailed compliance results for a single scan against a specific
              provider.
            </TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              {crossProviderEnabled ? (
                // Plain trigger, direct child of TabsList — same shape as
                // "Per Scan" and as ProviderPageTabs' tabs. shadcn's active
                // underline sizes itself off ``:not(:first-child)`` /
                // ``:last-child`` selectors on the trigger's OWN position
                // among its siblings; wrapping it in an extra element (as
                // the disabled branch below has to, for the tooltip-on-
                // disabled + badge requirements) breaks that and requires
                // hand-restoring every dropped padding/inset rule. Skipping
                // the wrapper whenever it isn't structurally necessary
                // keeps the common (enabled) case correct for free.
                <TabsTrigger value={COMPLIANCE_PAGE_TAB.CROSS_PROVIDER}>
                  Cross-Provider
                </TabsTrigger>
              ) : (
                // Disabled in OSS: the wrapper span (not the disabled
                // TabsTrigger) is the hover target so the tooltip still
                // fires, and it also hosts the upsell badge next to the
                // label. That makes the trigger the first/only child of the
                // span instead of TabsList, dropping the
                // ``[&:not(:first-child)]`` padding and the matching
                // ``[&:not(:first-child)]:after:left-4`` underline inset —
                // restore both by hand or the (invisible, disabled) active
                // underline would sit misaligned if this tab were ever
                // reachable.
                <span className="inline-flex items-center">
                  <TabsTrigger
                    value={COMPLIANCE_PAGE_TAB.CROSS_PROVIDER}
                    disabled
                    className="border-r-0 pl-4 after:left-4"
                  >
                    Cross-Provider
                  </TabsTrigger>
                  <CloudFeatureBadgeLink size="sm" className="ml-3" />
                </span>
              )}
            </TooltipTrigger>
            <TooltipContent side="bottom" sideOffset={6}>
              {crossProviderEnabled
                ? "Universal frameworks aggregated from the latest scan of every compatible provider in this tenant."
                : "Available in Prowler Cloud"}
            </TooltipContent>
          </Tooltip>
        </TabsList>
      </TooltipProvider>

      <TabsContent value={COMPLIANCE_PAGE_TAB.PER_SCAN} className="mt-0">
        {perScanContent}
      </TabsContent>

      {crossProviderEnabled && (
        <TabsContent
          value={COMPLIANCE_PAGE_TAB.CROSS_PROVIDER}
          className="mt-0"
        >
          {crossProviderContent}
        </TabsContent>
      )}
    </Tabs>
  );
};
