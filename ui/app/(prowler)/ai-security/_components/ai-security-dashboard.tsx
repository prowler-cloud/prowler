import { getAiSecurityOverview } from "@/app/(prowler)/ai-security/_actions";
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Skeleton,
} from "@/components/shadcn";
import type { ProviderProps } from "@/types/providers";

import { AiCompliance } from "./ai-compliance";
import { AiKpis } from "./ai-kpis";
import { AiSecurityEmptyState } from "./ai-security-empty-state";
import { AiStack } from "./ai-stack";
import { TopRisks } from "./top-risks";

// Skeleton heights are the rendered cards' heights at tablet and desktop widths.
const KPI_GRID = "grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-4";

export function AiSecurityDashboardSkeleton() {
  return (
    <div className="flex flex-col gap-6">
      <div className={KPI_GRID}>
        {[0, 1, 2, 3].map((index) => (
          <Skeleton key={index} className="h-[154px] rounded-xl xl:h-[186px]" />
        ))}
      </div>
      <Skeleton className="h-[314px] w-full rounded-xl" />
      <Skeleton className="h-[1155px] w-full rounded-xl lg:h-[660px]" />
      <Skeleton className="h-[469px] w-full rounded-xl" />
    </div>
  );
}

interface AiSecurityDashboardProps {
  /** The page's provider filters narrowed to the AI providers. */
  filters: Record<string, string>;
  /** The AI providers in scope; none shows the empty state. */
  providers: ProviderProps[];
}

export async function AiSecurityDashboard({
  filters,
  providers,
}: AiSecurityDashboardProps) {
  if (providers.length === 0) return <AiSecurityEmptyState />;

  const overview = await getAiSecurityOverview(filters, providers);

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
      <TopRisks risks={overview.topRisks} />
    </div>
  );
}
