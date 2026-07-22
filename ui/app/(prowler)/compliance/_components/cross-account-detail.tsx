import { Info } from "lucide-react";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import {
  type KnownProviderType,
  PROVIDER_DISPLAY_NAMES,
} from "@/types/providers";

import {
  getCrossAccountComplianceOverview,
  getLatestCrossAccountPdf,
} from "../_actions/cross-account";
import {
  getAggregatedInitialExpandedKeys,
  getAggregatedRequirementsTotals,
} from "../_lib/aggregated-compliance-detail";
import { toCrossAccountAccordionItems } from "../_lib/cross-account-accordion";
import {
  buildAccountExtrasMap,
  computeAccountBreakdown,
  crossAccountToMapperInput,
} from "../_lib/cross-account-adapter";
import { parseCrossAccountFilters } from "../_lib/cross-account-frameworks";
import { CROSS_PROVIDER_OVERVIEW_RESULT_STATUS } from "../_types";

import { AggregatedComplianceDetail } from "./aggregated-compliance-detail";
import { CrossProviderErrorAlert } from "./cross-provider-error-alert";
import type {
  CrossProviderAccountOption,
  CrossProviderGroupOption,
} from "./cross-provider-filters";
import { CrossProviderFilters } from "./cross-provider-filters";
import { CrossProviderPdfButton } from "./cross-provider-pdf-button";
import type { CoverageRow } from "./provider-coverage-card";
import { ProviderCoverageCard } from "./provider-coverage-card";

interface CrossAccountDetailProps {
  compliancetitle: string;
  complianceId: string;
  providerType: KnownProviderType;
  searchParams: Record<string, string | string[] | undefined>;
  targetSection?: string;
}

/**
 * Server island for the cross-account detail (`?mode=cross-account`): the
 * account-axis sibling of `CrossProviderDetail`. Fetches the roll-up of one
 * regular framework across every account of one provider type, funnels it
 * through the real framework mapper via the adapter, and renders the same
 * summary-charts + accordion layout with per-account augmentations.
 */
export const CrossAccountDetail = async ({
  compliancetitle,
  complianceId,
  providerType,
  searchParams,
  targetSection,
}: CrossAccountDetailProps) => {
  const filters = parseCrossAccountFilters(searchParams);

  const [overviewResponse, providersData, providerGroupsData] =
    await Promise.all([
      getCrossAccountComplianceOverview({
        complianceId,
        providerType,
        filters,
      }),
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
          No cross-account compliance data was returned for this framework. The
          view aggregates the latest completed scan of every account of this
          provider type — run a scan to populate it.
        </AlertDescription>
      </Alert>
    );
  }

  const attrs = overviewData.attributes;

  // Scoped to the EXACT scans the overview resolved (not the raw filters),
  // so an offered "Download latest" always matches the data on screen even
  // if an account finished a new scan between the two calls.
  const latestPdf = await getLatestCrossAccountPdf({
    complianceId,
    providerType,
    filters: { ...filters, scanIds: attrs.scan_ids },
  });

  const mapper = getComplianceMapper(attrs.framework);
  const { attributesData, requirementsData } = crossAccountToMapperInput(attrs);
  const data = mapper.mapComplianceData(attributesData, requirementsData);
  const extras = buildAccountExtrasMap(attrs);
  const coverageRows: CoverageRow[] = computeAccountBreakdown(attrs).map(
    (entry) => ({
      key: entry.id,
      label: entry.label,
      iconType: providerType,
      pass: entry.pass,
      fail: entry.fail,
      manual: entry.manual,
      score: entry.score,
    }),
  );

  const totals = getAggregatedRequirementsTotals(data);
  const accordionItems = toCrossAccountAccordionItems(
    data,
    extras,
    attrs.framework,
    attrs.accounts,
  );
  const topFailedResult = mapper.getTopFailedSections(data);

  const initialExpandedKeys = getAggregatedInitialExpandedKeys(
    data,
    accordionItems,
    targetSection,
  );

  const logoPath = getComplianceIcon(compliancetitle);

  const providerAccounts: CrossProviderAccountOption[] = (
    providersData?.data || []
  )
    .filter((provider) => provider.attributes.provider === providerType)
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
        <span className="truncate text-sm font-medium">
          {attrs.name || compliancetitle.split("-").join(" ")}
        </span>
      }
      description={
        <p className="text-text-neutral-tertiary flex items-center gap-1.5 text-xs">
          <ProviderTypeIcon type={providerType} size={14} />
          {PROVIDER_DISPLAY_NAMES[providerType]} · {attrs.accounts.length}{" "}
          {attrs.accounts.length === 1 ? "account" : "accounts"} aggregated ·{" "}
          {attrs.scan_ids.length}{" "}
          {attrs.scan_ids.length === 1 ? "scan" : "scans"}
        </p>
      }
      reportAction={
        <CrossProviderPdfButton
          complianceId={complianceId}
          providerType={providerType}
          filters={{ ...filters, scanIds: attrs.scan_ids }}
          latestPdf={latestPdf}
        />
      }
      filters={
        <CrossProviderFilters
          providerAccounts={providerAccounts}
          providerGroups={providerGroups}
        />
      }
      totals={totals}
      coverage={
        <ProviderCoverageCard
          rows={coverageRows}
          title="Account Coverage"
          emptyMessage="No scanned accounts for this framework yet."
        />
      }
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
