import { Info } from "lucide-react";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";

import {
  getCrossProviderComplianceOverview,
  getLatestCrossProviderPdf,
} from "../_actions/cross-provider";
import {
  getAggregatedInitialExpandedKeys,
  getAggregatedRequirementsTotals,
} from "../_lib/aggregated-compliance-detail";
import { toCrossProviderAccordionItems } from "../_lib/cross-provider-accordion";
import {
  buildRequirementExtrasMap,
  computeProviderBreakdown,
  crossProviderToMapperInput,
} from "../_lib/cross-provider-adapter";
import {
  CROSS_PROVIDER_FRAMEWORKS,
  parseCrossProviderFilters,
} from "../_lib/cross-provider-frameworks";
import { CROSS_PROVIDER_OVERVIEW_RESULT_STATUS } from "../_types";

import { AggregatedComplianceDetail } from "./aggregated-compliance-detail";
import { CrossProviderErrorAlert } from "./cross-provider-error-alert";
import type {
  CrossProviderAccountOption,
  CrossProviderGroupOption,
} from "./cross-provider-filters";
import { CrossProviderFilters } from "./cross-provider-filters";
import { CrossProviderHubLink } from "./cross-provider-hub-link";
import { CrossProviderPdfButton } from "./cross-provider-pdf-button";
import { ProviderCoverageCard } from "./provider-coverage-card";

interface CrossProviderDetailProps {
  compliancetitle: string;
  complianceId: string;
  searchParams: Record<string, string | string[] | undefined>;
  targetSection?: string;
}

/**
 * Server island for the cross-provider detail (`?mode=cross-provider`):
 * fetches the roll-up, funnels it through the real framework mapper via the
 * adapter, and renders the same summary-charts + accordion layout as the
 * per-scan detail with per-provider augmentations.
 */
export const CrossProviderDetail = async ({
  compliancetitle,
  complianceId,
  searchParams,
  targetSection,
}: CrossProviderDetailProps) => {
  const filters = parseCrossProviderFilters(searchParams);

  const [overviewResponse, providersData, providerGroupsData] =
    await Promise.all([
      getCrossProviderComplianceOverview({ complianceId, filters }),
      getAllProviders(),
      getAllProviderGroups(),
    ]);

  if (
    overviewResponse.status ===
    CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.ACTION_ERROR
  ) {
    return <CrossProviderErrorAlert result={overviewResponse.result} />;
  }

  if (
    overviewResponse.status === CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR
  ) {
    return <CrossProviderErrorAlert message={overviewResponse.message} />;
  }

  const overviewData = overviewResponse.response.data;

  if (!overviewData?.attributes) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertDescription>
          No cross-provider compliance data was returned for this framework.
          Universal frameworks aggregate the latest completed scan of every
          compatible provider — run a scan to populate this view.
        </AlertDescription>
      </Alert>
    );
  }

  const attrs = overviewData.attributes;

  // Scoped to the EXACT scans the overview resolved (not the raw filters), so
  // an offered "Download latest" always matches the data on screen even if a
  // provider finished a new scan between the two calls. The overview
  // aggregation dominates wall-clock; serializing this quick check is cheap.
  const latestPdf = await getLatestCrossProviderPdf({
    complianceId,
    filters: { ...filters, scanIds: attrs.scan_ids },
  });

  const mapper = getComplianceMapper(attrs.framework);
  const { attributesData, requirementsData } =
    crossProviderToMapperInput(attrs);
  const data = mapper.mapComplianceData(attributesData, requirementsData);
  const extras = buildRequirementExtrasMap(attrs);
  const providerBreakdown = computeProviderBreakdown(attrs);

  const totals = getAggregatedRequirementsTotals(data);
  const accordionItems = toCrossProviderAccordionItems(
    data,
    extras,
    attrs.framework,
  );
  const topFailedResult = mapper.getTopFailedSections(data);

  const initialExpandedKeys = getAggregatedInitialExpandedKeys(
    data,
    accordionItems,
    targetSection,
  );

  const catalogEntry = CROSS_PROVIDER_FRAMEWORKS.find(
    (entry) => entry.complianceId === complianceId,
  );
  const compatibleTypes =
    catalogEntry?.compatibleProviders ??
    providerBreakdown.map((b) => b.provider);
  const logoPath = getComplianceIcon(compliancetitle);

  const providerAccounts: CrossProviderAccountOption[] = (
    providersData?.data || []
  )
    .filter((provider) =>
      compatibleTypes.some((type) => type === provider.attributes.provider),
    )
    .map((provider) => ({
      id: provider.id,
      label: provider.attributes.alias
        ? `${provider.attributes.alias} (${provider.attributes.uid})`
        : provider.attributes.uid,
      type: provider.attributes.provider,
    }));

  const providerGroups: CrossProviderGroupOption[] = (
    providerGroupsData?.data || []
  ).map((group) => ({ id: group.id, name: group.attributes.name }));

  return (
    <AggregatedComplianceDetail
      compliancetitle={compliancetitle}
      logoPath={logoPath}
      title={
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-medium">
            {attrs.name || compliancetitle.split("-").join(" ")}
          </span>
          <CrossProviderHubLink complianceId={complianceId} />
        </div>
      }
      description={
        <p className="text-text-neutral-tertiary text-xs">
          {attrs.providers.length} of {compatibleTypes.length} compatible
          providers scanned · {attrs.scan_ids.length}{" "}
          {attrs.scan_ids.length === 1 ? "scan" : "scans"} aggregated
        </p>
      }
      reportAction={
        <CrossProviderPdfButton
          complianceId={complianceId}
          filters={{ ...filters, scanIds: attrs.scan_ids }}
          latestPdf={latestPdf}
        />
      }
      filters={
        <CrossProviderFilters
          providerTypes={compatibleTypes}
          providerAccounts={providerAccounts}
          providerGroups={providerGroups}
        />
      }
      totals={totals}
      coverage={<ProviderCoverageCard breakdown={providerBreakdown} />}
      topFailed={{
        sections: topFailedResult.items,
        dataType: topFailedResult.type,
        prepopulated: topFailedResult.prepopulated,
      }}
      accordionItems={accordionItems}
      initialExpandedKeys={initialExpandedKeys}
    />
  );
};
