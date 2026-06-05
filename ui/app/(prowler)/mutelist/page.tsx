import { SkeletonBoundary } from "@/components/shadcn";
import { ContentLayout } from "@/components/ui";
import { SearchParamsProps } from "@/types/components";

import { MuteRulesTable, MuteRulesTableSkeleton } from "./_components/simple";
import { MutelistTabs } from "./mutelist-tabs";

export default async function MutelistPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const searchParamsKey = JSON.stringify(resolvedSearchParams);

  return (
    <ContentLayout title="Mutelist" icon="lucide:volume-x">
      <MutelistTabs
        simpleContent={
          <SkeletonBoundary
            key={searchParamsKey}
            fallback={<MuteRulesTableSkeleton />}
          >
            <MuteRulesTable searchParams={resolvedSearchParams} />
          </SkeletonBoundary>
        }
      />
    </ContentLayout>
  );
}
