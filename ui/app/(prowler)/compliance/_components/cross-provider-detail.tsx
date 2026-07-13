import { Info } from "lucide-react";
import Image from "next/image";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import {
  ClientAccordionWrapper,
  RequirementsStatusCard,
  TopFailedSectionsCard,
} from "@/components/compliance";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Card } from "@/components/shadcn/card/card";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import type { Framework, RequirementsTotals } from "@/types/compliance";

import {
  getCrossProviderComplianceOverview,
  getLatestCrossProviderPdf,
} from "../_actions/cross-provider";
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

  const totals: RequirementsTotals = data.reduce(
    (acc: RequirementsTotals, framework: Framework) => ({
      pass: acc.pass + framework.pass,
      fail: acc.fail + framework.fail,
      manual: acc.manual + framework.manual,
    }),
    { pass: 0, fail: 0, manual: 0 },
  );
  const accordionItems = toCrossProviderAccordionItems(
    data,
    extras,
    attrs.framework,
  );
  const topFailedResult = mapper.getTopFailedSections(data);

  // Same `${framework.name}-${category.name}` key scheme as the per-scan
  // detail, so ?section= deep links (e.g. from Top Failed Sections) work.
  const initialExpandedKeys: string[] = [];
  if (targetSection) {
    const candidates = new Set(
      data.map((framework: Framework) => `${framework.name}-${targetSection}`),
    );
    const match = accordionItems.find((item) => candidates.has(item.key));
    if (match) {
      initialExpandedKeys.push(match.key);
    }
  }

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
    <div className="flex flex-col gap-8">
      {/* Header card — same structure as the per-scan detail: identity row
          (logo + context) with the report action top-right, filters below
          (lighthouse-settings card pattern). */}
      <Card variant="base" className="w-full gap-4 p-4 md:p-5">
        <div className="flex w-full flex-col gap-4">
          <div className="flex w-full items-center justify-between gap-4">
            <div className="flex min-w-0 items-center gap-4">
              {logoPath && (
                <div className="relative h-12 w-12 shrink-0">
                  <Image
                    src={logoPath}
                    alt={`${compliancetitle} logo`}
                    fill
                    className="rounded-lg border border-gray-300 bg-white object-contain p-0"
                  />
                </div>
              )}
              <div className="flex min-w-0 flex-col gap-0.5">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="truncate text-sm font-medium">
                    {attrs.name || compliancetitle.split("-").join(" ")}
                  </span>
                  <CrossProviderHubLink complianceId={complianceId} />
                </div>
                <p className="text-text-neutral-tertiary text-xs">
                  {attrs.providers.length} of {compatibleTypes.length}{" "}
                  compatible providers scanned · {attrs.scan_ids.length}{" "}
                  {attrs.scan_ids.length === 1 ? "scan" : "scans"} aggregated
                </p>
              </div>
            </div>
            <div className="shrink-0">
              <CrossProviderPdfButton
                complianceId={complianceId}
                filters={{ ...filters, scanIds: attrs.scan_ids }}
                latestPdf={latestPdf}
              />
            </div>
          </div>

          <CrossProviderFilters
            providerTypes={compatibleTypes}
            providerAccounts={providerAccounts}
            providerGroups={providerGroups}
          />
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-[minmax(280px,400px)_minmax(280px,360px)_1fr]">
        <RequirementsStatusCard
          pass={totals.pass}
          fail={totals.fail}
          manual={totals.manual}
        />
        <ProviderCoverageCard breakdown={providerBreakdown} />
        <TopFailedSectionsCard
          sections={topFailedResult.items}
          dataType={topFailedResult.type}
          prepopulated={topFailedResult.prepopulated}
        />
      </div>

      <ClientAccordionWrapper
        items={accordionItems}
        defaultExpandedKeys={initialExpandedKeys}
        scrollToKey={initialExpandedKeys[0]}
      />
    </div>
  );
};
