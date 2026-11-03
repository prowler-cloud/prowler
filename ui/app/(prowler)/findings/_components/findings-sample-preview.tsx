import Link from "next/link";

import { FindingsGroupTable } from "@/components/findings/table";
import { Button } from "@/components/shadcn";
import { SamplePreviewBanner } from "@/components/shared/sample-preview/sample-preview-banner";
import { SAMPLE_ACCOUNT } from "@/lib/sample-preview/sample-dataset";
import { filterSampleFindingGroups } from "@/lib/sample-preview/sample-findings";
import { SAMPLE_PREVIEW_PAGE } from "@/lib/sample-preview/sample-preview-events";
import type { SamplePreviewActive } from "@/lib/sample-preview/sample-preview-state";
import type { SearchParamsProps } from "@/types/components";

// Scoping to the sample scan is what makes every drill-down action answer
// from the sample records instead of the API.
const SAMPLE_SCAN_FILTERS: Record<string, string> = {
  "filter[scan]": SAMPLE_ACCOUNT.scanId,
};

interface FindingsSamplePreviewProps {
  state: SamplePreviewActive;
  /** Overview drill-downs and the table's search and sorting controls. */
  searchParams?: SearchParamsProps;
}

/** Sample finding groups: no filter controls, no metadata (so no Lighthouse context). */
export function FindingsSamplePreview({
  state,
  searchParams = {},
}: FindingsSamplePreviewProps) {
  const { groups, filtered, resourceFilters } =
    filterSampleFindingGroups(searchParams);

  return (
    <>
      <SamplePreviewBanner state={state} page={SAMPLE_PREVIEW_PAGE.FINDINGS} />
      {filtered && (
        <p className="text-text-neutral-tertiary mb-4 text-sm">
          Showing {groups.length} sample checks matching your filters.{" "}
          <Button variant="link" size="link-sm" asChild>
            <Link href="/findings">Show all</Link>
          </Button>
        </p>
      )}
      <FindingsGroupTable
        // Key resets client state (selection, drill-down) when data changes.
        key={groups.map((group) => group.id).join(",")}
        data={groups}
        resolvedFilters={{ ...SAMPLE_SCAN_FILTERS, ...resourceFilters }}
        hasHistoricalData
      />
    </>
  );
}
