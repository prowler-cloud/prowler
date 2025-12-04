"use server";

import { Spacer } from "@heroui/spacer";

import { getLatestFindings } from "@/actions/findings/findings";
import { LinkToFindings } from "@/components/overview";
import { ColumnNewFindingsToDate } from "@/components/overview/new-findings-table/table/column-new-findings-to-date";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib/helper";
import { mapProviderFiltersForFindingsObject } from "@/lib/provider-helpers";
import { FindingProps, SearchParamsProps } from "@/types";

import { LighthouseBanner } from "@/components/lighthouse/banner";

import { pickFilterParams } from "../../_lib/filter-params";

interface FindingsViewSSRProps {
  searchParams: SearchParamsProps;
}

export async function FindingsViewSSR({ searchParams }: FindingsViewSSRProps) {
  const page = 1;
  const sort = "severity,-inserted_at";

  const defaultFilters = {
    "filter[status]": "FAIL",
    "filter[delta]": "new",
  };

  const filters = pickFilterParams(searchParams);
  const mappedFilters = mapProviderFiltersForFindingsObject(filters);
  const combinedFilters = { ...defaultFilters, ...mappedFilters };

  const findingsData = await getLatestFindings({
    query: undefined,
    page,
    sort,
    filters: combinedFilters,
  });

  const resourceDict = createDict("resources", findingsData);
  const scanDict = createDict("scans", findingsData);
  const providerDict = createDict("providers", findingsData);

  const expandedFindings = findingsData?.data
    ? (findingsData.data as FindingProps[]).map((finding) => {
        const scan = scanDict[finding.relationships?.scan?.data?.id];
        const resource =
          resourceDict[finding.relationships?.resources?.data?.[0]?.id];
        const provider = providerDict[scan?.relationships?.provider?.data?.id];

        return {
          ...finding,
          relationships: { scan, resource, provider },
        };
      })
    : [];

  const expandedResponse = {
    ...findingsData,
    data: expandedFindings,
  };

  return (
    <div className="flex w-full flex-col">
      <LighthouseBanner />
      <div className="relative flex w-full">
        <div className="flex w-full items-center gap-2">
          <h3 className="text-sm font-bold uppercase">
            Latest new failing findings
          </h3>
          <p className="text-text-neutral-tertiary text-xs">
            Showing the latest 10 new failing findings by severity.
          </p>
        </div>
        <div className="absolute -top-6 right-0">
          <LinkToFindings />
        </div>
      </div>
      <Spacer y={4} />

      <DataTable
        key={`dashboard-findings-${Date.now()}`}
        columns={ColumnNewFindingsToDate}
        data={(expandedResponse?.data || []) as FindingProps[]}
      />
    </div>
  );
}
