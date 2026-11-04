import { cache } from "react";

import { getProviders } from "@/actions/providers";
import { getScans, getScansByState } from "@/actions/scans";
import { auth } from "@/auth.config";
import { isCloud } from "@/lib/shared/env";
import { SCAN_STATES } from "@/types/attack-paths";

import {
  resolveSamplePreviewState,
  type RunningScan,
  type SamplePreviewState,
} from "./sample-preview-state";

const INACTIVE: SamplePreviewState = { active: false };

interface ScanRowAttributes {
  progress?: number | null;
}

interface ScanRow {
  id: string;
  attributes: ScanRowAttributes;
}

const hasRows = (response: unknown): boolean | undefined => {
  const data = (response as { data?: unknown } | undefined)?.data;
  return Array.isArray(data) ? data.length > 0 : undefined;
};

// Undefined when the lookup failed, so the page doesn't offer a scan that may be running.
const toRunningScan = (response: unknown): RunningScan | null | undefined => {
  const data = (response as { data?: ScanRow[] } | undefined)?.data;
  if (!Array.isArray(data)) return undefined;
  const scan = data[0];
  if (!scan) return null;
  return { id: scan.id, progress: scan.attributes.progress ?? 0 };
};

/** Resolved once per request, so every page section shares one answer. */
export const getSamplePreviewState = cache(
  async (): Promise<SamplePreviewState> => {
    // Prowler Cloud only: self-hosted deployments never show sample data.
    const enabled = isCloud();
    if (!enabled) return INACTIVE;

    const session = await auth();
    const canManageProviders =
      session?.user?.permissions?.manage_providers === true;
    if (!canManageProviders) return INACTIVE;

    try {
      // Most tenants already have a completed scan: one lookup settles it.
      const hasCompletedScan = hasRows(await getScansByState());
      if (hasCompletedScan !== false) return INACTIVE;

      const [providers, runningScans] = await Promise.all([
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
        canManageProviders,
        hasCompletedScan,
        hasProviders: hasRows(providers),
        runningScan: toRunningScan(runningScans),
      });
    } catch {
      // The scans actions throw on 5xx: the real page wins.
      return INACTIVE;
    }
  },
);
