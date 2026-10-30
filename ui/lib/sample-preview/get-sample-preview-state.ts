import { cache } from "react";

import { getProviders } from "@/actions/providers";
import { getScans, getScansByState } from "@/actions/scans";
import { isSamplePreviewEnabled } from "@/lib/sample-preview-access";
import { SCAN_STATES } from "@/types/attack-paths";

import {
  resolveSamplePreviewState,
  type RunningScan,
  type SamplePreviewState,
} from "./sample-preview-state";

interface ScanRow {
  id: string;
  attributes: { progress?: number | null };
}

const hasRows = (response: unknown): boolean | undefined => {
  const data = (response as { data?: unknown } | undefined)?.data;
  return Array.isArray(data) ? data.length > 0 : undefined;
};

const toRunningScan = (response: unknown): RunningScan | null => {
  const data = (response as { data?: ScanRow[] } | undefined)?.data;
  const scan = Array.isArray(data) ? data[0] : undefined;
  if (!scan) return null;
  return { id: scan.id, progress: scan.attributes.progress ?? 0 };
};

/** Resolved once per request, so every page section shares one answer. */
export const getSamplePreviewState = cache(
  async (): Promise<SamplePreviewState> => {
    const enabled = await isSamplePreviewEnabled();
    if (!enabled) return { active: false };

    const [completedScans, providers, runningScans] = await Promise.all([
      getScansByState(),
      getProviders({ page: 1, pageSize: 1 }),
      getScans({
        pageSize: 1,
        sort: "-inserted_at",
        filters: {
          "filter[state__in]": `${SCAN_STATES.AVAILABLE},${SCAN_STATES.EXECUTING}`,
        },
        fields: { scans: "state,progress" },
      }),
    ]);

    return resolveSamplePreviewState({
      enabled,
      hasCompletedScan: hasRows(completedScans),
      hasProviders: hasRows(providers),
      runningScan: toRunningScan(runningScans),
    });
  },
);
