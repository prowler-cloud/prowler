"use server";

import { getLatestFindings } from "@/actions/findings/findings";
import { LighthouseBanner } from "@/components/lighthouse/banner";
import { LinkToFindings } from "@/components/overview";
import { ColumnNewFindingsToDate } from "@/components/overview/new-findings-table/table/column-new-findings-to-date";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib/helper";
import { FindingProps, SearchParamsProps } from "@/types";

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
  const combinedFilters = { ...defaultFilters, ...filters };

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
    <div className="flex w-full flex-col gap-6">
      <LighthouseBanner />
      <div className="relative w-full flex-col justify-between md:flex-row">
        <div className="flex w-full flex-col items-start gap-2 md:flex-row md:items-center">
          <h3 className="text-sm font-bold text-nowrap whitespace-nowrap uppercase">
            Latest new failing findings
          </h3>
          <p className="text-text-neutral-tertiary text-xs whitespace-nowrap">
            Showing the latest 10 new failing findings by severity.
          </p>
          <LinkToFindings />
        </div>
      </div>

      <DataTable
        key={`dashboard-findings-${Date.now()}`}
        columns={ColumnNewFindingsToDate}
        data={(expandedResponse?.data || []) as FindingProps[]}
      />
    </div>
  );
}
