import Link from "next/link";

import {
  getRealtimeCostAnomaly,
  getRealtimeDemo,
  getRealtimeInsight,
} from "@/app/(prowler)/realtime/_actions";
import { RealtimeEmptyState } from "@/app/(prowler)/realtime/_components/shared/realtime-empty-state";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import {
  formatMoney,
  parseAnomalyId,
} from "@/app/(prowler)/realtime/_lib/display";
import {
  configurationHref,
  firstParam,
  REALTIME_PARAM,
} from "@/app/(prowler)/realtime/_lib/routes";
import type {
  RealtimeAnomalyPayload,
  RealtimeResult,
} from "@/app/(prowler)/realtime/_types";
import type { RealtimeTabProps } from "@/app/(prowler)/realtime/_types/view";
import { Button, Card, Skeleton } from "@/components/shadcn";

import { CostAnomaliesTable } from "./cost-anomalies-table";
import { CostSeriesList } from "./cost-series-list";

const loadAnomaly = async (
  providerId: string,
  demo: boolean,
  id: string | undefined,
): Promise<RealtimeResult<RealtimeAnomalyPayload> | null> => {
  if (!id) return null;
  if (demo) return getRealtimeDemo("anomaly");
  const parsed = parseAnomalyId(id);
  if (!parsed) return { ok: false, status: 404, error: "Unknown anomaly." };
  return getRealtimeCostAnomaly({ providerId, ...parsed });
};

export async function CostTab({
  providerId,
  demo,
  searchParams,
}: RealtimeTabProps) {
  const anomalyId = firstParam(searchParams, REALTIME_PARAM.ANOMALY);
  const [result, anomaly] = await Promise.all([
    demo ? getRealtimeDemo("cost") : getRealtimeInsight("cost", providerId),
    loadAnomaly(providerId, demo, anomalyId),
  ]);
  if (!result.ok) return <RealtimePanelError failure={result} />;

  const cost = result.data;
  if (!cost.enabled) {
    return (
      <RealtimeEmptyState
        title="Cost anomalies are off"
        description="Turn them on to spot sudden spend increases per service and region. Prowler reads AWS Cost Explorer about every 6 hours, and AWS bills each request."
        action={
          <Button variant="outline" size="sm" asChild>
            <Link href={configurationHref(providerId, "cost")}>
              Set up cost anomalies
            </Link>
          </Button>
        }
      />
    );
  }

  const tiles = [
    { label: "Latest day", value: formatMoney(cost.total.today) },
    { label: "Last 30 days", value: formatMoney(cost.total.total) },
    { label: "Anomalies", value: String(cost.anomalies.length) },
  ];

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {tiles.map((tile) => (
          <Card key={tile.label} variant="base" className="gap-1">
            <span className="text-text-neutral-tertiary text-xs">
              {tile.label}
            </span>
            <span className="text-text-neutral-primary text-2xl font-bold">
              {tile.value}
            </span>
          </Card>
        ))}
      </div>
      <section className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <h3 className="text-text-neutral-primary text-base font-semibold">
            Anomalies
          </h3>
          <p className="text-text-neutral-tertiary text-sm">
            A day counts when spend is at least {cost.thresholds.min_ratio}x the
            14-day average and at least {formatMoney(cost.thresholds.min_delta)}{" "}
            above it.
          </p>
        </div>
        <CostAnomaliesTable
          anomalies={cost.anomalies}
          anomaly={anomaly}
          thresholds={cost.thresholds}
        />
      </section>
      <section className="flex flex-col gap-3">
        <h3 className="text-text-neutral-primary text-base font-semibold">
          Daily cost by service
        </h3>
        <CostSeriesList series={cost.series} />
      </section>
    </div>
  );
}

export function CostTabSkeleton() {
  return (
    <div className="flex flex-col gap-6" aria-hidden="true">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {Array.from({ length: 3 }, (_, index) => (
          <Skeleton key={index} className="h-[76px] rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-64 w-full rounded-xl" />
      <Skeleton className="h-72 w-full rounded-xl" />
    </div>
  );
}
