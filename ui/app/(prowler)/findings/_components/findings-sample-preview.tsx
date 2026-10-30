import { FindingsGroupTable } from "@/components/findings/table";
import { SamplePreviewBanner } from "@/components/shared/sample-preview/sample-preview-banner";
import { SAMPLE_FINDING_GROUPS } from "@/lib/sample-preview/sample-findings";
import { SAMPLE_PREVIEW_PAGE } from "@/lib/sample-preview/sample-preview-events";
import type { SamplePreviewActive } from "@/lib/sample-preview/sample-preview-state";

const NO_FILTERS: Record<string, string> = {};

interface FindingsSamplePreviewProps {
  state: SamplePreviewActive;
}

/** Sample finding groups: no filters, no metadata (so no Lighthouse context), inert rows. */
export function FindingsSamplePreview({ state }: FindingsSamplePreviewProps) {
  return (
    <>
      <SamplePreviewBanner state={state} page={SAMPLE_PREVIEW_PAGE.FINDINGS} />
      <div inert>
        <FindingsGroupTable
          data={SAMPLE_FINDING_GROUPS}
          resolvedFilters={NO_FILTERS}
          hasHistoricalData={false}
        />
      </div>
    </>
  );
}
