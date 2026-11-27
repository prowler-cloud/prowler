import { Bot } from "lucide-react";
import { notFound } from "next/navigation";
import { Suspense } from "react";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import {
  AiSecurityDashboard,
  AiSecurityDashboardSkeleton,
  AiSecurityUpgradePrompt,
} from "@/app/(prowler)/ai-security/_components";
import {
  AI_SECURITY_PREVIEW,
  aiProvidersInScope,
  aiScopeFilters,
} from "@/app/(prowler)/ai-security/_lib/overview";
import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import { ProviderGroupSelector } from "@/components/filters/provider-group-selector";
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

  const resolvedSearchParams = await searchParams;
  const { preview } = resolvedSearchParams;

  if (preview === AI_SECURITY_PREVIEW.LOCKED || (await isAiSecurityLocked())) {
    return (
      <ContentLayout title="AI Security" icon={<Bot />}>
        <AiSecurityUpgradePrompt />
      </ContentLayout>
    );
  }

  const [providersData, providerGroupsData] = await Promise.all([
    getAllProviders(),
    getAllProviderGroups(),
  ]);

  const providers = providersData?.data ?? [];
  const filters = aiScopeFilters(resolvedSearchParams);
  // `?preview=empty` shows the empty state whatever the tenant has.
  const aiProviders =
    filters && preview !== AI_SECURITY_PREVIEW.EMPTY
      ? aiProvidersInScope(providers, filters)
      : [];

  return (
    <ContentLayout title="AI Security" icon={<Bot />}>
      {/* One row shared evenly by the filters, as on Overview. */}
      <div className="mb-6 flex flex-col gap-6 md:flex-row md:*:min-w-0 md:*:flex-1">
        <ProviderAccountSelectors providers={providers} />
        <ProviderGroupSelector groups={providerGroupsData?.data ?? []} />
      </div>
      <Suspense fallback={<AiSecurityDashboardSkeleton />}>
        <AiSecurityDashboard filters={filters ?? {}} providers={aiProviders} />
      </Suspense>
    </ContentLayout>
  );
}
