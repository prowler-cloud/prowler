import { SkeletonTableFindings } from "@/components/findings/table";
import { ContentLayout } from "@/components/shadcn/content-layout";

import { FindingsFiltersSkeleton } from "./_components/findings-filters-skeleton";

export default function FindingsLoading() {
  return (
    <ContentLayout
      title="Findings"
      icon="lucide:tag"
      onboardingAction={{ flowId: "explore-findings" }}
    >
      <div className="mb-6">
        <FindingsFiltersSkeleton />
      </div>
      <SkeletonTableFindings />
    </ContentLayout>
  );
}
