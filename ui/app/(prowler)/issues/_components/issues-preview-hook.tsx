import { getFindingsBySeverity } from "@/actions/overview/findings/findings";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import {
  getPremiumPreviewHook,
  PREMIUM_PREVIEW_FEATURE,
} from "@/lib/premium-preview";

export async function IssuesPreviewHook() {
  // The action rethrows 5xx; the preview must still render without counts.
  const severity = await getFindingsBySeverity({
    filters: { "filter[status]": "FAIL" },
  }).catch(() => undefined);
  const attributes = severity?.data?.attributes;

  return getPremiumPreviewHook(
    PREMIUM_PREVIEW_FEATURE.EXPLOITABILITY_ISSUES,
    attributes
      ? { critical: attributes.critical ?? 0, high: attributes.high ?? 0 }
      : null,
  );
}

export function IssuesPreviewHookSkeleton() {
  return <Skeleton className="h-5 w-full max-w-xl" />;
}
