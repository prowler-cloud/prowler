import type { LatestCrossProviderPdfReport } from "@/actions/compliances";
import type { CrossProviderComplianceOverviewAttributes } from "@/types/compliance";
import type { ProviderGroup } from "@/types/components";
import type { ProviderProps } from "@/types/providers";

import { CrossProviderDetailClient } from "./cross-provider-detail-client";

interface CrossProviderDetailProps {
  attributes: CrossProviderComplianceOverviewAttributes;
  /** Provider accounts of a type compatible with this framework (not
   *  filtered by connection status) — feeds the provider type / account
   *  filter controls. */
  providers: ProviderProps[];
  /** Every provider group in the tenant (not narrowed by framework
   *  compatibility — groups can span multiple provider types, same as
   *  every other provider-group filter in the app). */
  providerGroups: ProviderGroup[];
  /** Raw ``filter[provider_type__in]`` / ``filter[provider_id__in]`` /
   *  ``filter[provider_groups__in]`` / ``filter[region__in]`` values from the
   *  URL — threaded down to the "Generate PDF" button. */
  providerTypeFilter?: string;
  providerIdFilter?: string;
  providerGroupsFilter?: string;
  regionFilter?: string;
  /** A previously-generated PDF matching these exact filters, resolved
   *  server-side alongside ``attributes`` — ``null`` means none exists yet
   *  (or it went stale) for the current filters, so the "Generate PDF"
   *  button shows "Generate" instead of "Download". */
  latestPdfReport: LatestCrossProviderPdfReport | null;
}

/**
 * Cross-provider compliance detail view.
 *
 * Server component shell — passes the API response straight through to
 * the client orchestrator. The orchestrator owns interactive state
 * (search term, status quick toggles, domain anchor scroll, drawer
 * selection) so every panel of the redesigned 3-pane header stays in
 * sync with the accordion below.
 */
export const CrossProviderDetail = ({
  attributes,
  providers,
  providerGroups,
  providerTypeFilter,
  providerIdFilter,
  providerGroupsFilter,
  regionFilter,
  latestPdfReport,
}: CrossProviderDetailProps) => {
  return (
    <CrossProviderDetailClient
      attributes={attributes}
      providers={providers}
      providerGroups={providerGroups}
      providerTypeFilter={providerTypeFilter}
      providerIdFilter={providerIdFilter}
      providerGroupsFilter={providerGroupsFilter}
      regionFilter={regionFilter}
      latestPdfReport={latestPdfReport}
    />
  );
};
