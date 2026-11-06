import {
  getRealtimeActions,
  getRealtimeDemo,
  getRealtimeDetections,
  getRealtimeInsight,
} from "@/app/(prowler)/realtime/_actions";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import {
  ATTENTION_ACTION_STATUSES,
  toAttentionItems,
} from "@/app/(prowler)/realtime/_lib/attention";
import { getOverview } from "@/app/(prowler)/realtime/_lib/cached";
import { REALTIME_DETECTION_STATUS } from "@/app/(prowler)/realtime/_types";
import type { RealtimeTabProps } from "@/app/(prowler)/realtime/_types/view";
import { Card, CardContent, Skeleton } from "@/components/shadcn";

import { CostCard } from "./cost-card";
import { NeedsAttention } from "./needs-attention";
import { OverviewKpis } from "./overview-kpis";
import { PostureTimeline } from "./posture-timeline";
import { SimulationCard } from "./simulation-card";

const ATTENTION_LIMIT = 6;

const loadAttention = async (providerId: string, demo: boolean) => {
  if (demo) {
    const [detections, actions] = await Promise.all([
      getRealtimeDemo("detections"),
      getRealtimeDemo("actions"),
    ]);
    return toAttentionItems(
      detections.ok ? detections.data.items : [],
      actions.ok ? actions.data.items : [],
      ATTENTION_LIMIT,
    );
  }
  const [detections, actions] = await Promise.all([
    getRealtimeDetections({
      providerId,
      statusIn: [REALTIME_DETECTION_STATUS.VIOLATION],
      pageSize: ATTENTION_LIMIT,
    }),
    getRealtimeActions({
      providerId,
      statusIn: [...ATTENTION_ACTION_STATUSES],
      pageSize: ATTENTION_LIMIT,
    }),
  ]);
  return toAttentionItems(
    detections.ok ? detections.data.items : [],
    actions.ok ? actions.data.items : [],
    ATTENTION_LIMIT,
  );
};

export async function OverviewTab({ providerId, demo }: RealtimeTabProps) {
  const [overview, simulation, timeline, attention] = await Promise.all([
    getOverview(providerId, demo),
    demo
      ? getRealtimeDemo("simulation")
      : getRealtimeInsight("simulation", providerId),
    demo
      ? getRealtimeDemo("timeline")
      : getRealtimeInsight("timeline", providerId),
    loadAttention(providerId, demo),
  ]);

  // The header already explains a failed overview.
  if (!overview.ok) return null;
  const cost = overview.data.cost;

  return (
    <div className="flex flex-col gap-4">
      <OverviewKpis overview={overview.data} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <NeedsAttention providerId={providerId} items={attention} />
        </div>
        <SimulationCard
          providerId={providerId}
          demo={demo}
          result={simulation}
        />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card
          variant="base"
          padding="lg"
          className={cost.enabled ? "lg:col-span-2" : "lg:col-span-3"}
        >
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-col gap-1">
              <h3 className="text-text-neutral-primary text-base font-semibold">
                Posture over time
              </h3>
              <p className="text-text-neutral-tertiary text-sm">
                Checks per scan, and what Prowler Realtime fixed or proposed in
                between.
              </p>
            </div>
            {timeline.ok ? (
              <PostureTimeline
                providerId={providerId}
                timeline={timeline.data}
              />
            ) : (
              <RealtimePanelError failure={timeline} />
            )}
          </CardContent>
        </Card>
        {cost.enabled && <CostCard providerId={providerId} cost={cost} />}
      </div>
    </div>
  );
}

export function OverviewTabSkeleton() {
  return (
    <div className="flex flex-col gap-4" aria-busy="true">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton key={index} className="h-[124px] rounded-xl" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Skeleton className="h-[360px] rounded-xl lg:col-span-2" />
        <Skeleton className="h-[360px] rounded-xl" />
      </div>
      <Skeleton className="h-[630px] rounded-xl" />
    </div>
  );
}
