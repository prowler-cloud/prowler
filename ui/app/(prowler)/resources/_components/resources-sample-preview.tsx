import { ResourcesFilters } from "@/components/resources/resources-filters";
import { ResourcesTableWithSelection } from "@/components/resources/table";
import { SamplePreviewBanner } from "@/components/shared/sample-preview/sample-preview-banner";
import { FilterTransitionWrapper } from "@/contexts";
import { SAMPLE_FILTER_PROVIDER } from "@/lib/sample-preview/sample-findings";
import { SAMPLE_PREVIEW_PAGE } from "@/lib/sample-preview/sample-preview-events";
import type { SamplePreviewActive } from "@/lib/sample-preview/sample-preview-state";
import {
  filterSampleResources,
  SAMPLE_RESOURCE_FILTER_OPTIONS,
} from "@/lib/sample-preview/sample-resources";
import type { SearchParamsProps } from "@/types";

interface ResourcesSamplePreviewProps {
  state: SamplePreviewActive;
  searchParams: SearchParamsProps;
}

/** Sample resources with the real filter bar, table and resource drawer. */
export function ResourcesSamplePreview({
  state,
  searchParams,
}: ResourcesSamplePreviewProps) {
  const { data, metadata } = filterSampleResources(searchParams);

  return (
    <>
      <SamplePreviewBanner state={state} page={SAMPLE_PREVIEW_PAGE.RESOURCES} />
      <FilterTransitionWrapper>
        <div className="mb-6">
          <ResourcesFilters
            providers={[SAMPLE_FILTER_PROVIDER]}
            providerGroups={[]}
            uniqueRegions={SAMPLE_RESOURCE_FILTER_OPTIONS.regions}
            uniqueServices={SAMPLE_RESOURCE_FILTER_OPTIONS.services}
            uniqueResourceTypes={SAMPLE_RESOURCE_FILTER_OPTIONS.types}
            uniqueGroups={SAMPLE_RESOURCE_FILTER_OPTIONS.groups}
          />
        </div>
        <ResourcesTableWithSelection
          data={data}
          metadata={metadata}
          contributeLighthouseContext={false}
        />
      </FilterTransitionWrapper>
    </>
  );
}
