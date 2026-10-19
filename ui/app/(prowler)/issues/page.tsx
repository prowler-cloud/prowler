import { ShieldAlert } from "lucide-react";
import { notFound } from "next/navigation";
import { Suspense } from "react";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import { ProviderGroupSelector } from "@/components/filters/provider-group-selector";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { FeatureFlagGate } from "@/components/shared/feature-flag-gate";
import { FEATURE_FLAG } from "@/lib/feature-flags";
import { isCloud } from "@/lib/shared/env";
import { SearchParamsProps } from "@/types";

import { IssuesList } from "./_components/issues-list";

export default async function Issues({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  if (!isCloud()) notFound();

  const resolvedSearchParams = await searchParams;
  const [providersData, providerGroupsData] = await Promise.all([
    getAllProviders(),
    getAllProviderGroups(),
  ]);

  return (
    <ContentLayout title="Issues" icon={<ShieldAlert />}>
      {/* Deployment gate above (notFound); per-account rollout here. The route
          stays reachable by URL, so the off state explains itself. */}
      <FeatureFlagGate
        flag={FEATURE_FLAG.ISSUES}
        fallback={
          <p className="text-text-neutral-tertiary text-sm">
            Issues is not available for this account yet.
          </p>
        }
      >
        <Suspense
          fallback={
            <p className="text-text-neutral-tertiary text-sm">
              Loading issues…
            </p>
          }
        >
          <IssuesList
            searchParams={resolvedSearchParams}
            filters={
              // The three scope selectors share one row on desktop, like the
              // other list pages.
              <div className="mb-6 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
                <ProviderAccountSelectors
                  providers={providersData?.data ?? []}
                />
                <ProviderGroupSelector
                  groups={providerGroupsData?.data ?? []}
                />
              </div>
            }
          />
        </Suspense>
      </FeatureFlagGate>
    </ContentLayout>
  );
}
