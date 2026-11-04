import Link from "next/link";

import { formatMoney } from "@/app/(prowler)/realtime/_lib/display";
import {
  REALTIME_PARAM,
  REALTIME_TAB,
  realtimeHref,
} from "@/app/(prowler)/realtime/_lib/routes";
import type { RealtimeCostOn } from "@/app/(prowler)/realtime/_types";
import { Badge, Card, CardContent } from "@/components/shadcn";

interface CostCardProps {
  providerId: string;
  cost: RealtimeCostOn;
}

/** Today's spend and the anomalies behind it. */
export function CostCard({ providerId, cost }: CostCardProps) {
  return (
    <Card variant="base" padding="lg" className="h-full">
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex flex-col gap-1">
            <h3 className="text-text-neutral-primary text-base font-semibold">
              Cost today
            </h3>
            <p className="text-text-neutral-tertiary text-sm">
              From Cost Explorer, every 6 hours.
            </p>
          </div>
          {cost.anomaly_count > 0 && (
            <Badge variant="warning">
              {cost.anomaly_count}{" "}
              {cost.anomaly_count === 1 ? "anomaly" : "anomalies"}
            </Badge>
          )}
        </div>
        {!cost.available ? (
          <p className="text-text-neutral-tertiary text-sm">
            No cost figures yet. They appear after the next Cost Explorer read.
          </p>
        ) : (
          <>
            <div className="flex gap-6">
              <div className="flex flex-col">
                <span className="text-text-neutral-primary text-2xl font-bold">
                  {formatMoney(cost.today)}
                </span>
                <span className="text-text-neutral-tertiary text-xs">
                  Today
                </span>
              </div>
              <div className="flex flex-col">
                <span className="text-text-neutral-primary text-2xl font-bold">
                  {formatMoney(cost.total)}
                </span>
                <span className="text-text-neutral-tertiary text-xs">
                  Last 30 days
                </span>
              </div>
            </div>
            <ul className="flex flex-col">
              {cost.anomalies.map((anomaly) => (
                <li
                  key={anomaly.id}
                  className="border-border-neutral-secondary border-t"
                >
                  <Link
                    href={realtimeHref(providerId, REALTIME_TAB.COST, {
                      [REALTIME_PARAM.ANOMALY]: anomaly.id,
                    })}
                    className="text-text-neutral-primary hover:bg-bg-neutral-tertiary flex justify-between gap-3 py-2.5 text-sm"
                  >
                    <span className="truncate">
                      {anomaly.short_service} · {anomaly.region}
                    </span>
                    <span className="text-text-warning-primary shrink-0 font-semibold">
                      {anomaly.ratio.toFixed(1)}x · +
                      {formatMoney(anomaly.delta)}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  );
}
