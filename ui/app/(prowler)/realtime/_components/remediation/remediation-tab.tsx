import {
  getRealtimeAction,
  getRealtimeActions,
  getRealtimeDemo,
} from "@/app/(prowler)/realtime/_actions";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import { getOverview } from "@/app/(prowler)/realtime/_lib/cached";
import {
  localPage,
  matchesFilter,
  toTableMetadata,
} from "@/app/(prowler)/realtime/_lib/demo-list";
import {
  firstParam,
  listParam,
  pageParam,
  pageSizeParam,
  REALTIME_PARAM,
} from "@/app/(prowler)/realtime/_lib/routes";
import type { RealtimeAction } from "@/app/(prowler)/realtime/_types";
import type { RealtimeTabProps } from "@/app/(prowler)/realtime/_types/view";
import { Card, Skeleton } from "@/components/shadcn";

import {
  type RemediationCounts,
  remediationCounts,
} from "./remediation-counts";
import { RemediationTable } from "./remediation-table";

const KIND_FILTER = "filter[kind__in]";
const STATUS_FILTER = "filter[status__in]";

const countsOf = (actions: RealtimeAction[]): Record<string, number> =>
  actions.reduce<Record<string, number>>((counts, action) => {
    counts[action.status] = (counts[action.status] ?? 0) + 1;
    return counts;
  }, {});

export async function RemediationTab({
  providerId,
  demo,
  canManage,
  searchParams,
}: RealtimeTabProps) {
  const kindIn = listParam(searchParams, KIND_FILTER);
  const statusIn = listParam(searchParams, STATUS_FILTER);
  const selectedId = firstParam(searchParams, REALTIME_PARAM.ACTION);
  const paging = {
    page: pageParam(searchParams),
    pageSize: pageSizeParam(searchParams),
  };

  const [actionsResult, overviewResult] = await Promise.all([
    demo
      ? getRealtimeDemo("actions")
      : getRealtimeActions({ providerId, kindIn, statusIn, ...paging }),
    getOverview(providerId, demo),
  ]);
  if (!actionsResult.ok) return <RealtimePanelError failure={actionsResult} />;

  const page = demo
    ? localPage(actionsResult.data.items, {
        keep: (action) =>
          matchesFilter(kindIn, action.kind) &&
          matchesFilter(statusIn, action.status),
        ...paging,
      })
    : actionsResult.data;
  const counts = remediationCounts(
    overviewResult.ok
      ? overviewResult.data.actions
      : countsOf(actionsResult.data.items),
  );

  const known = page.items.find((action) => action.id === selectedId);
  const selected =
    known ??
    (selectedId && !demo
      ? await getRealtimeAction(selectedId).then((result) =>
          result.ok ? result.data : null,
        )
      : null) ??
    null;

  return (
    <div className="flex flex-col gap-6">
      <RemediationSummary counts={counts} />
      <RemediationTable
        providerId={providerId}
        actions={page.items}
        metadata={toTableMetadata(page)}
        selected={selected}
        canWrite={canManage && !demo}
        demo={demo}
        filtered={kindIn.length > 0 || statusIn.length > 0}
      />
    </div>
  );
}

function RemediationSummary({ counts }: { counts: RemediationCounts }) {
  const tiles = [
    { label: "Fixed and verified", value: counts.verified },
    { label: "Pull requests opened", value: counts.prsOpened },
    { label: "Recorded in dry run", value: counts.dryRun },
  ];
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
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
      <Card
        variant={counts.attention > 0 ? "danger" : "base"}
        className="gap-1"
      >
        <span className="text-text-neutral-tertiary text-xs">
          Need attention
        </span>
        <span className="text-text-neutral-primary text-2xl font-bold">
          {counts.attention}
        </span>
      </Card>
    </div>
  );
}

export function RemediationTabSkeleton() {
  return (
    <div className="flex flex-col gap-6" aria-hidden="true">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton key={index} className="h-[76px] rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-9 w-[28rem] rounded-lg" />
      <Skeleton className="h-[440px] w-full rounded-xl" />
    </div>
  );
}
