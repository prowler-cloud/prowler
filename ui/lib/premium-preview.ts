import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

export const PREMIUM_PREVIEW_FEATURE = {
  EXPLOITABILITY_ISSUES: CLOUD_UPGRADE_FEATURE.EXPLOITABILITY_ISSUES,
  REALTIME: CLOUD_UPGRADE_FEATURE.REALTIME,
} as const;

export type PremiumPreviewFeature =
  (typeof PREMIUM_PREVIEW_FEATURE)[keyof typeof PREMIUM_PREVIEW_FEATURE];

interface FailCounts {
  critical: number;
  high: number;
}

const formatCount = (value: number) => value.toLocaleString("en-US");

export function getPremiumPreviewHook(
  feature: PremiumPreviewFeature,
  failCounts: FailCounts | null,
): string {
  if (feature === PREMIUM_PREVIEW_FEATURE.REALTIME) {
    return "Your Local Server checks your accounts when a scan runs. Realtime reacts to CloudTrail events minutes after a risky change.";
  }

  if (!failCounts || failCounts.critical + failCounts.high === 0) {
    return "Once your Local Server has scan results, Exploitability Issues groups the failed findings into attack patterns ranked by how exploitable they are.";
  }

  return `Your latest scans have ${formatCount(failCounts.critical)} critical and ${formatCount(failCounts.high)} high FAIL findings. Exploitability Issues groups them into attack patterns ranked by how exploitable they are.`;
}
