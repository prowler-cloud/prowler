import { getAiSecurityOverview } from "@/app/(prowler)/ai-security/_lib/mock-overview";
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Skeleton,
} from "@/components/shadcn";

import { AiCompliance } from "./ai-compliance";
import { AiInventory } from "./ai-inventory";
import { AiKpis } from "./ai-kpis";
import { AiSecurityEmptyState } from "./ai-security-empty-state";
import { AiStack } from "./ai-stack";
import { TopRisks } from "./top-risks";

// Skeleton heights are the rendered cards' heights at tablet and desktop widths.
const KPI_GRID = "grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-4";
// Top risks reads as a list and takes the wider share once both fit a row.
const BOTTOM_GRID = "grid grid-cols-1 gap-6 xl:grid-cols-[7fr_5fr]";

export function AiSecurityDashboardSkeleton() {
  return (
    <div className="flex flex-col gap-6">
      <div className={KPI_GRID}>
        {[0, 1, 2, 3].map((index) => (
          <Skeleton key={index} className="h-[154px] rounded-xl xl:h-[186px]" />
        ))}
      </div>
      <Skeleton className="h-[706px] w-full rounded-xl xl:h-[334px]" />
      <Skeleton className="h-[1155px] w-full rounded-xl lg:h-[660px]" />
      <div className={BOTTOM_GRID}>
        <Skeleton className="h-[469px] rounded-xl" />
        <Skeleton className="h-[500px] rounded-xl" />
      </div>
    </div>
  );
}

export async function AiSecurityDashboard({ preview }: { preview?: string }) {
  const overview = await getAiSecurityOverview(preview);

  if (!overview) {
    return (
      <Alert variant="error">
        <AlertTitle>AI Security could not be loaded</AlertTitle>
        <AlertDescription>Reload the page to try again.</AlertDescription>
      </Alert>
    );
  }

  if (overview.pass + overview.fail + overview.manual === 0) {
    return <AiSecurityEmptyState />;
  }

  return (
    <div className="flex flex-col gap-6">
      <AiKpis overview={overview} />
      <AiStack layers={overview.layers} />
      <AiCompliance frameworks={overview.frameworks} />
      <div className={BOTTOM_GRID}>
        <TopRisks risks={overview.topRisks} />
        <AiInventory items={overview.inventory} />
      </div>
    </div>
  );
}
