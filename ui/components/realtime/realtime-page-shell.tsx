import { Radar } from "lucide-react";
import { notFound } from "next/navigation";
import type { ReactNode } from "react";

import { getAllProviders } from "@/actions/providers";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { FeatureFlagGate } from "@/components/shared/feature-flag-gate";
import { FEATURE_FLAG } from "@/lib/feature-flags";
import type { RealtimeProviderOption } from "@/lib/realtime/providers";
import { isCloud } from "@/lib/shared/env";

export const REALTIME_PRODUCT_NAME =
  "Prowler Realtime Detection and Remediation";

/**
 * The frame every Realtime page shares: Cloud only (404 elsewhere), the
 * per-account feature flag, and the account's AWS providers (the feature reads
 * CloudTrail and fixes AWS resources, so nothing else is offered).
 */
export async function RealtimePageShell({
  children,
}: {
  // May be async: page lookups then run only after the Cloud gate below.
  children: (
    providers: RealtimeProviderOption[],
  ) => ReactNode | Promise<ReactNode>;
}) {
  if (!isCloud()) notFound();

  const providersData = await getAllProviders();
  const providers = (providersData?.data ?? [])
    .filter((provider) => provider.attributes.provider === "aws")
    .map((provider) => ({
      id: provider.id,
      uid: provider.attributes.uid,
      alias: provider.attributes.alias || null,
    }));

  return (
    <ContentLayout title={REALTIME_PRODUCT_NAME} icon={<Radar />}>
      {/* Deployment gate above (notFound); per-account rollout here. */}
      <FeatureFlagGate
        flag={FEATURE_FLAG.REALTIME}
        fallback={
          <p className="text-text-neutral-tertiary text-sm">
            {REALTIME_PRODUCT_NAME} is not available for this account yet.
          </p>
        }
      >
        {await children(providers)}
      </FeatureFlagGate>
    </ContentLayout>
  );
}
