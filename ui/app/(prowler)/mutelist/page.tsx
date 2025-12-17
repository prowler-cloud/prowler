import { Suspense } from "react";

import { ContentLayout } from "@/components/ui";

import { MuteRulesTable, MuteRulesTableSkeleton } from "./_components/simple";
import { MutelistTabs } from "./mutelist-tabs";

export default function MutelistPage() {
  return (
    <ContentLayout title="Mutelist" icon="lucide:volume-x">
      <MutelistTabs
        simpleContent={
          <Suspense fallback={<MuteRulesTableSkeleton />}>
            <MuteRulesTable />
          </Suspense>
        }
      />
    </ContentLayout>
  );
}
