import { FindingsFilters } from "@/components/findings/findings-filters";
import { FindingsGroupTable } from "@/components/findings/table";
import { AutoRefresh } from "@/components/scans/auto-refresh";
import { SamplePreviewBanner } from "@/components/shared/sample-preview/sample-preview-banner";
import { FilterTransitionWrapper } from "@/contexts";
import { SAMPLE_ACCOUNT } from "@/lib/sample-preview/sample-dataset";
import {
  filterSampleFindingGroups,
  SAMPLE_FILTER_PROVIDER,
  SAMPLE_FINDING_FILTER_OPTIONS,
} from "@/lib/sample-preview/sample-findings";
import { SAMPLE_PREVIEW_PAGE } from "@/lib/sample-preview/sample-preview-events";
import {
  SAMPLE_PREVIEW_STAGE,
  type SamplePreviewActive,
} from "@/lib/sample-preview/sample-preview-state";
import type { SearchParamsProps } from "@/types/components";

// Scoping to the sample scan is what makes every drill-down action answer
// from the sample records instead of the API.
const SAMPLE_SCAN_FILTERS: Record<string, string> = {
  "filter[scan]": SAMPLE_ACCOUNT.scanId,
};

interface FindingsSamplePreviewProps {
  state: SamplePreviewActive;
  /** The filter bar, Overview drill-downs and the table's search and sorting. */
  searchParams?: SearchParamsProps;
}

/** Sample finding groups with the real filter bar; options come from the records. */
export function FindingsSamplePreview({
  state,
  searchParams = {},
}: FindingsSamplePreviewProps) {
  const { groups, resourceFilters } = filterSampleFindingGroups(searchParams);

  return (
    <>
      {/* Re-checks on the server whether the running scan's findings can take over. */}
      <AutoRefresh
        hasExecutingScan={state.stage === SAMPLE_PREVIEW_STAGE.SCAN_RUNNING}
      />
      <SamplePreviewBanner state={state} page={SAMPLE_PREVIEW_PAGE.FINDINGS} />
      <FilterTransitionWrapper>
        <div className="mb-6">
          {/* No scans or groups: only the sample account and its own values. */}
          <FindingsFilters
            providers={[SAMPLE_FILTER_PROVIDER]}
            providerGroups={[]}
            completedScanIds={[]}
            scanDetails={[]}
            uniqueRegions={SAMPLE_FINDING_FILTER_OPTIONS.regions}
            uniqueServices={SAMPLE_FINDING_FILTER_OPTIONS.services}
            uniqueResourceTypes={SAMPLE_FINDING_FILTER_OPTIONS.resourceTypes}
            uniqueCategories={SAMPLE_FINDING_FILTER_OPTIONS.categories}
            uniqueGroups={SAMPLE_FINDING_FILTER_OPTIONS.groups}
          />
        </div>
        <FindingsGroupTable
          // Key resets client state (selection, drill-down) when data or filters change.
          key={`${groups.map((group) => group.id).join(",")}|${JSON.stringify(resourceFilters)}`}
          data={groups}
          resolvedFilters={{ ...SAMPLE_SCAN_FILTERS, ...resourceFilters }}
          hasHistoricalData
        />
      </FilterTransitionWrapper>
    </>
  );
}
