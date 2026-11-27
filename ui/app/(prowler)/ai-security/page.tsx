import { Bot } from "lucide-react";
import { notFound } from "next/navigation";
import { Suspense } from "react";

import { getAllProviders } from "@/actions/providers";
import {
  AiSecurityDashboard,
  AiSecurityDashboardSkeleton,
  AiSecurityUpgradePrompt,
} from "@/app/(prowler)/ai-security/_components";
import {
  AI_SCOPE,
  AI_SECURITY_PREVIEW,
  aiProviders,
} from "@/app/(prowler)/ai-security/_lib/overview";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { isAiSecurityLocked } from "@/lib/ai-security-access";
import { isCloud } from "@/lib/shared/env";
import { SearchParamsProps } from "@/types";

export default async function AiSecurityPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  if (!isCloud()) notFound();

  const { preview } = await searchParams;

  if (preview === AI_SECURITY_PREVIEW.LOCKED || (await isAiSecurityLocked())) {
    return (
      <ContentLayout title="AI Security" icon={<Bot />}>
        <AiSecurityUpgradePrompt />
      </ContentLayout>
    );
  }

  const providersData = await getAllProviders();
  // `?preview=empty` shows the empty state whatever the tenant has.
  const providers =
    preview === AI_SECURITY_PREVIEW.EMPTY
      ? []
      : aiProviders(providersData?.data ?? []);

  return (
    <ContentLayout title="AI Security" icon={<Bot />}>
      <Suspense fallback={<AiSecurityDashboardSkeleton />}>
        <AiSecurityDashboard filters={AI_SCOPE} providers={providers} />
      </Suspense>
    </ContentLayout>
  );
}
