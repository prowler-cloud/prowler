import { ATTENTION_ACTION_STATUSES } from "@/app/(prowler)/realtime/_lib/attention";
import { REALTIME_ACTION_STATUS } from "@/app/(prowler)/realtime/_types";

/** Statuses a person should look at. */
export interface RemediationCounts {
  verified: number;
  prsOpened: number;
  dryRun: number;
  attention: number;
}

/** Summary counts from the overview's `actions` (counts per status). */
export const remediationCounts = (
  byStatus: Record<string, number>,
): RemediationCounts => ({
  verified: byStatus[REALTIME_ACTION_STATUS.FIXED_VERIFIED] ?? 0,
  prsOpened: byStatus[REALTIME_ACTION_STATUS.PR_OPENED] ?? 0,
  dryRun: byStatus[REALTIME_ACTION_STATUS.DRY_RUN] ?? 0,
  attention: ATTENTION_ACTION_STATUSES.reduce(
    (sum, status) => sum + (byStatus[status] ?? 0),
    0,
  ),
});
