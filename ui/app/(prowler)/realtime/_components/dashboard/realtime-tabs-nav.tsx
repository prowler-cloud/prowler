"use client";

import { useRouter } from "next/navigation";

import {
  parseTab,
  REALTIME_TAB,
  REALTIME_TAB_LABELS,
  REALTIME_TAB_ORDER,
  realtimeHref,
  type RealtimeTab,
} from "@/app/(prowler)/realtime/_lib/routes";
import {
  REALTIME_ACTION_STATUS,
  REALTIME_DETECTION_STATUS,
  type RealtimeOverviewPayload,
} from "@/app/(prowler)/realtime/_types";
import { Badge } from "@/components/shadcn";
import { Tabs, TabsList, TabsTrigger } from "@/components/shadcn/tabs/tabs";

interface RealtimeTabsNavProps {
  providerId: string;
  activeTab: RealtimeTab;
  overview: RealtimeOverviewPayload | null;
}

/** Counts that deserve a look, shown next to the tab label. */
const tabCounts = (
  overview: RealtimeOverviewPayload | null,
): Partial<Record<RealtimeTab, number>> => {
  if (!overview) return {};
  const actions = overview.actions ?? {};
  return {
    [REALTIME_TAB.DETECTIONS]:
      overview.detections?.[REALTIME_DETECTION_STATUS.VIOLATION] ?? 0,
    [REALTIME_TAB.REMEDIATION]:
      (actions[REALTIME_ACTION_STATUS.FIX_FAILED] ?? 0) +
      (actions[REALTIME_ACTION_STATUS.STILL_FAILING] ?? 0) +
      (actions[REALTIME_ACTION_STATUS.PR_BLOCKED] ?? 0),
    [REALTIME_TAB.COST]: overview.cost.enabled
      ? overview.cost.anomaly_count
      : 0,
  };
};

export function RealtimeTabsNav({
  providerId,
  activeTab,
  overview,
}: RealtimeTabsNavProps) {
  const router = useRouter();
  const counts = tabCounts(overview);

  return (
    <Tabs
      value={activeTab}
      onValueChange={(value) =>
        router.push(realtimeHref(providerId, parseTab(value)), {
          scroll: false,
        })
      }
    >
      {/* Labels keep their width; the row scrolls when space runs out. */}
      <div className="overflow-x-auto">
        <TabsList className="w-max">
          {REALTIME_TAB_ORDER.map((tab) => (
            <TabsTrigger
              key={tab}
              value={tab}
              adornment={
                counts[tab] ? (
                  <Badge
                    variant={
                      tab === REALTIME_TAB.DETECTIONS ? "error" : "warning"
                    }
                    size="sm"
                    aria-label={`${counts[tab]} need attention`}
                  >
                    {counts[tab]}
                  </Badge>
                ) : null
              }
            >
              {REALTIME_TAB_LABELS[tab]}
            </TabsTrigger>
          ))}
        </TabsList>
      </div>
    </Tabs>
  );
}
