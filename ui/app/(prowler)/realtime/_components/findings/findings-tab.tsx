import {
  getRealtimeDemo,
  getRealtimeInsight,
} from "@/app/(prowler)/realtime/_actions";
import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import {
  localPage,
  toTableMetadata,
} from "@/app/(prowler)/realtime/_lib/demo-list";
import {
  ROUTE_LEGEND,
  routeBadge,
  signalLabel,
} from "@/app/(prowler)/realtime/_lib/display";
import { pageParam, pageSizeParam } from "@/app/(prowler)/realtime/_lib/routes";
import {
  REALTIME_ROUTE,
  type RealtimeSignal,
} from "@/app/(prowler)/realtime/_types";
import type { RealtimeTabProps } from "@/app/(prowler)/realtime/_types/view";
import { Card, Skeleton } from "@/components/shadcn";

import { FindingsTable } from "./findings-table";

export async function FindingsTab({
  providerId,
  demo,
  searchParams,
}: RealtimeTabProps) {
  const result = demo
    ? await getRealtimeDemo("findings")
    : await getRealtimeInsight("findings", providerId);
  if (!result.ok) return <RealtimePanelError failure={result} />;

  const page = localPage(result.data.findings, {
    page: pageParam(searchParams),
    pageSize: pageSizeParam(searchParams),
  });

  return (
    <div className="flex flex-col gap-4">
      <SignalsCard signals={result.data.signals} />
      <div className="flex min-w-0 flex-col gap-4">
        <p className="text-text-neutral-tertiary text-sm">
          Open failing findings from the latest scan, ranked by severity and by
          what is happening in the account right now.
        </p>
        <FindingsTable findings={page.items} metadata={toTableMetadata(page)} />
        <ul className="text-text-neutral-tertiary flex flex-col gap-1.5 text-xs">
          {Object.values(REALTIME_ROUTE).map((route) => (
            <li key={route} className="flex flex-wrap items-center gap-2">
              <RealtimeBadge descriptor={routeBadge(route)} />
              {ROUTE_LEGEND[route]}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function SignalsCard({ signals }: { signals: RealtimeSignal[] }) {
  return (
    <Card variant="base" className="gap-3">
      <div className="flex flex-col gap-1">
        <h3 className="text-text-neutral-primary text-sm font-semibold">
          Signals in the last 24 h
        </h3>
        <p className="text-text-neutral-tertiary text-xs">
          Activity that raises the rank of findings in the same service.
        </p>
      </div>
      {signals.length === 0 ? (
        <p className="text-text-neutral-tertiary text-sm">
          No unusual activity.
        </p>
      ) : (
        <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {signals.map((signal) => (
            <li
              key={`${signal.signal}:${signal.service}:${signal.region}`}
              className="border-border-neutral-secondary flex items-start justify-between gap-3 rounded-lg border px-3 py-2"
            >
              <div className="flex min-w-0 flex-col gap-0.5">
                <span className="text-text-neutral-primary text-sm">
                  {signalLabel(signal.signal)}
                </span>
                <span className="text-text-neutral-tertiary text-xs">
                  {[signal.service, signal.region].filter(Boolean).join(" · ")}
                </span>
              </div>
              <span className="text-text-neutral-primary text-sm font-semibold">
                {signal.count}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function FindingsTabSkeleton() {
  return (
    <div className="flex flex-col gap-4" aria-hidden="true">
      <Skeleton className="h-36 w-full rounded-xl" />
      <Skeleton className="h-5 w-[32rem] max-w-full rounded" />
      <Skeleton className="h-[480px] w-full rounded-xl" />
    </div>
  );
}
