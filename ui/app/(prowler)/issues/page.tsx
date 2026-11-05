import { ShieldAlert } from "lucide-react";
import { notFound } from "next/navigation";
import { Suspense } from "react";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import { ProviderGroupSelector } from "@/components/filters/provider-group-selector";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { SamplePreviewBanner } from "@/components/shared/sample-preview/sample-preview-banner";
import { getSamplePreviewState } from "@/lib/sample-preview/get-sample-preview-state";
import { SAMPLE_ACCOUNT } from "@/lib/sample-preview/sample-dataset";
import { SAMPLE_PREVIEW_PAGE } from "@/lib/sample-preview/sample-preview-events";
import { isCloud } from "@/lib/shared/env";
import { SearchParamsProps } from "@/types";

import { IssuesList } from "./_components/issues-list";

const SAMPLE_PROVIDER_UIDS = {
  [SAMPLE_ACCOUNT.providerId]: SAMPLE_ACCOUNT.uid,
};

export default async function Issues({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  if (!isCloud()) notFound();

  const resolvedSearchParams = await searchParams;
  const samplePreview = await getSamplePreviewState();
  if (samplePreview.active) {
    return (
      <ContentLayout title="Issues" icon={<ShieldAlert />}>
        <SamplePreviewBanner
          state={samplePreview}
          page={SAMPLE_PREVIEW_PAGE.ISSUES}
        />
        {/* No scope selectors: the sample account is not one of theirs. */}
        <IssuesList
          searchParams={resolvedSearchParams}
          sample
          providerUids={SAMPLE_PROVIDER_UIDS}
        />
      </ContentLayout>
    );
  }

  const [providersData, providerGroupsData] = await Promise.all([
    getAllProviders(),
    getAllProviderGroups(),
  ]);

  const providers = providersData?.data ?? [];
  // The issue only references its provider; the uid shows in the panel.
  const providerUids = Object.fromEntries(
    providers.map((provider) => [provider.id, provider.attributes.uid]),
  );

  return (
    <ContentLayout title="Issues" icon={<ShieldAlert />}>
      <Suspense
        fallback={
          <p className="text-text-neutral-tertiary text-sm">Loading issues…</p>
        }
      >
        <IssuesList
          searchParams={resolvedSearchParams}
          providerUids={providerUids}
          filters={
            // The three scope selectors share one row on desktop, like the
            // other list pages.
            <div className="mb-6 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
              <ProviderAccountSelectors providers={providers} />
              <ProviderGroupSelector groups={providerGroupsData?.data ?? []} />
            </div>
          }
        />
      </Suspense>
    </ContentLayout>
  );
}
