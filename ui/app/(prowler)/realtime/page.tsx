import { Radar } from "lucide-react";
import { Suspense } from "react";

import { RealtimeDashboard } from "@/app/(prowler)/realtime/_components/dashboard/realtime-dashboard";
import { RealtimeDashboardSkeleton } from "@/app/(prowler)/realtime/_components/dashboard/realtime-dashboard-skeleton";
import type { RealtimeSearchParams } from "@/app/(prowler)/realtime/_lib/routes";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { PremiumPreviewPage } from "@/components/shared/premium-preview-page";
import {
  getPremiumPreviewHook,
  PREMIUM_PREVIEW_FEATURE,
} from "@/lib/premium-preview";
import { isCloud } from "@/lib/shared/env";

interface RealtimePageProps {
  searchParams: Promise<RealtimeSearchParams>;
}

export default async function RealtimePage({
  searchParams,
}: RealtimePageProps) {
  if (!isCloud()) {
    return (
      <ContentLayout title="Realtime" icon={<Radar />}>
        <PremiumPreviewPage
          feature={PREMIUM_PREVIEW_FEATURE.REALTIME}
          personalHook={getPremiumPreviewHook(
            PREMIUM_PREVIEW_FEATURE.REALTIME,
            null,
          )}
        />
      </ContentLayout>
    );
  }
  const params = await searchParams;

  return (
    <ContentLayout title="Realtime" icon={<Radar />}>
      <Suspense fallback={<RealtimeDashboardSkeleton />}>
        <RealtimeDashboard searchParams={params} />
      </Suspense>
    </ContentLayout>
  );
}
