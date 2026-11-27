import { Suspense } from "react";

import {
  getAiFrameworks,
  getAiSecurityOverview,
} from "@/app/(prowler)/ai-security/_actions";
import { installedScope } from "@/app/(prowler)/ai-security/_lib/overview";
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

const AiComplianceSkeleton = () => (
  <Skeleton className="h-[394px] w-full rounded-xl" />
);

export function AiSecurityDashboardSkeleton() {
  return (
    <div className="flex flex-col gap-6">
      <div className={KPI_GRID}>
        {[0, 1, 2, 3].map((index) => (
          <Skeleton key={index} className="h-[154px] rounded-xl xl:h-[186px]" />
        ))}
      </div>
      <Skeleton className="h-[652px] w-full rounded-xl" />
      <AiComplianceSkeleton />
      <Skeleton className="h-[469px] w-full rounded-xl" />
    </div>
  );
}

interface AiSecurityDashboardProps {
  /** The page's scope: the AI-SPM provider types. */
  filters: Record<string, string>;
  /** The AI-SPM providers the stack lists; none shows the empty state. */
  providers: ProviderProps[];
}

/** Streams on its own, so the slower compliance calls hold back only this card. */
async function AiComplianceSSR({
  frameworksPromise,
}: {
  frameworksPromise: ReturnType<typeof getAiFrameworks>;
}) {
  return <AiCompliance frameworks={await frameworksPromise} />;
}

export async function AiSecurityDashboard({
  filters: pageFilters,
  providers,
}: AiSecurityDashboardProps) {
  const filters = installedScope(pageFilters, providers);
  if (!filters) {
    return <AiSecurityEmptyState />;
  }

  // Started before the overview is awaited, so both load in parallel. A failed
  // overview never awaits it, so a rejection is caught here: the card's error state.
  const frameworksPromise = getAiFrameworks(filters).catch(() => null);
  const overview = await getAiSecurityOverview(filters, providers);

  if (!overview) {
    return (
      <Alert variant="error">
        <AlertTitle>AI Security could not be loaded</AlertTitle>
        <AlertDescription>Reload the page to try again.</AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <AiKpis overview={overview} filters={filters} />
      <AiStack layers={overview.layers} filters={filters} />
      <Suspense fallback={<AiComplianceSkeleton />}>
        <AiComplianceSSR frameworksPromise={frameworksPromise} />
      </Suspense>
      <TopRisks risks={overview.topRisks} filters={filters} />
    </div>
  );
}
