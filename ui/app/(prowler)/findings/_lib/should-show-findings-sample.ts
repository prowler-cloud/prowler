import { getFindings } from "@/actions/findings";
import { getScan } from "@/actions/scans";
import { resolveFindingScanDateFilters } from "@/lib/findings-scan-filters";
import {
  SAMPLE_PREVIEW_STAGE,
  type SamplePreviewState,
} from "@/lib/sample-preview/sample-preview-state";

const hasRows = (response: unknown): boolean => {
  const data = (response as { data?: unknown } | undefined)?.data;
  return Array.isArray(data) && data.length > 0;
};

/**
 * Sample data stands in on Findings until the running first scan has stored
 * findings, then the early findings view takes over.
 */
export async function shouldShowFindingsSample(
  preview: SamplePreviewState,
): Promise<boolean> {
  if (!preview.active) return false;
  if (preview.stage !== SAMPLE_PREVIEW_STAGE.SCAN_RUNNING) return true;
  if (!preview.runningScan) return true;

  try {
    // The findings endpoint needs a date range, taken from the scan itself.
    const filters = await resolveFindingScanDateFilters({
      filters: { "filter[scan]": preview.runningScan.id },
      scans: [],
      loadScan: async (scanId) => (await getScan(scanId))?.data,
    });
    const findings = await getFindings({ pageSize: 1, filters });

    return !hasRows(findings);
  } catch {
    // The scan action throws on 5xx: a failed lookup keeps the sample.
    return true;
  }
}
