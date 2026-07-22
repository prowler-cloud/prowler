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
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Card } from "@/components/shadcn/card/card";
import { getComplianceMapper } from "@/lib/compliance/compliance-mapper";
import type { Framework, RequirementsTotals } from "@/types/compliance";
import {
  type KnownProviderType,
  PROVIDER_DISPLAY_NAMES,
} from "@/types/providers";

import {
  getCrossAccountComplianceOverview,
  getLatestCrossAccountPdf,
} from "../_actions/cross-account";
import { toCrossAccountAccordionItems } from "../_lib/cross-account-accordion";
import {
  buildAccountExtrasMap,
  computeAccountBreakdown,
  crossAccountToMapperInput,
} from "../_lib/cross-account-adapter";
import { parseCrossAccountFilters } from "../_lib/cross-account-frameworks";
import { CROSS_PROVIDER_OVERVIEW_RESULT_STATUS } from "../_types";

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

  const totals: RequirementsTotals = data.reduce(
    (acc: RequirementsTotals, framework: Framework) => ({
      pass: acc.pass + framework.pass,
      fail: acc.fail + framework.fail,
      manual: acc.manual + framework.manual,
    }),
    { pass: 0, fail: 0, manual: 0 },
  );
  const accordionItems = toCrossAccountAccordionItems(
    data,
    extras,
    attrs.framework,
    attrs.accounts,
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
    <div className="flex flex-col gap-8">
      {/* Header card — same structure as the cross-provider detail: identity
          row (logo + context), filters below. */}
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
                <span className="truncate text-sm font-medium">
                  {attrs.name || compliancetitle.split("-").join(" ")}
                </span>
                <p className="text-text-neutral-tertiary flex items-center gap-1.5 text-xs">
                  <ProviderTypeIcon type={providerType} size={14} />
                  {PROVIDER_DISPLAY_NAMES[providerType]} ·{" "}
                  {attrs.accounts.length}{" "}
                  {attrs.accounts.length === 1 ? "account" : "accounts"}{" "}
                  aggregated · {attrs.scan_ids.length}{" "}
                  {attrs.scan_ids.length === 1 ? "scan" : "scans"}
                </p>
              </div>
            </div>
            <div className="shrink-0">
              <CrossProviderPdfButton
                complianceId={complianceId}
                providerType={providerType}
                filters={{ ...filters, scanIds: attrs.scan_ids }}
                latestPdf={latestPdf}
              />
            </div>
          </div>

          {/* No providerTypes: the type select is meaningless here — the
              provider type is fixed by the framework being viewed. */}
          <CrossProviderFilters
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
        <ProviderCoverageCard
          rows={coverageRows}
          title="Account Coverage"
          emptyMessage="No scanned accounts for this framework yet."
        />
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
