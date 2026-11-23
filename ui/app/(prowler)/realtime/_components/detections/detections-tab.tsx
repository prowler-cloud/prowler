import {
  getRealtimeActions,
  getRealtimeDemo,
  getRealtimeDetection,
  getRealtimeDetections,
} from "@/app/(prowler)/realtime/_actions";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
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
import type {
  RealtimeAction,
  RealtimeDetection,
  RealtimePage,
  RealtimeResult,
} from "@/app/(prowler)/realtime/_types";
import type { RealtimeTabProps } from "@/app/(prowler)/realtime/_types/view";
import { Skeleton } from "@/components/shadcn";

import { DetectionsTable } from "./detections-table";

const STATUS_FILTER = "filter[status__in]";
const SEVERITY_FILTER = "filter[severity__in]";
const RULE_FILTER = "filter[rule_id]";

interface SelectedDetection {
  detection: RealtimeDetection | null;
  actions: RealtimeAction[];
}

const loadDemo = async (
  props: RealtimeTabProps,
): Promise<
  RealtimeResult<{ page: RealtimePage<RealtimeDetection> } & SelectedDetection>
> => {
  const { searchParams } = props;
  const [detections, actions] = await Promise.all([
    getRealtimeDemo("detections"),
    getRealtimeDemo("actions"),
  ]);
  if (!detections.ok) return detections;
  const statusIn = listParam(searchParams, STATUS_FILTER);
  const severityIn = listParam(searchParams, SEVERITY_FILTER);
  const ruleId = firstParam(searchParams, RULE_FILTER);
  const selectedId = firstParam(searchParams, REALTIME_PARAM.DETECTION);
  const detection =
    detections.data.items.find((item) => item.id === selectedId) ?? null;
  return {
    ok: true,
    data: {
      page: localPage(detections.data.items, {
        keep: (item) =>
          matchesFilter(statusIn, item.status) &&
          matchesFilter(severityIn, item.severity) &&
          (!ruleId || item.rule_id === ruleId),
        page: pageParam(searchParams),
        pageSize: pageSizeParam(searchParams),
      }),
      detection,
      // Sample actions are not linked to detections: match by resource.
      actions:
        detection && actions.ok
          ? actions.data.items.filter(
              (action) => action.resource_uid === detection.resource,
            )
          : [],
    },
  };
};

const loadSelected = async (
  providerId: string,
  detectionId: string | undefined,
  page: RealtimePage<RealtimeDetection>,
): Promise<SelectedDetection> => {
  if (!detectionId) return { detection: null, actions: [] };
  const known = page.items.find((item) => item.id === detectionId);
  const [detection, actions] = await Promise.all([
    known
      ? Promise.resolve({ ok: true as const, data: known })
      : getRealtimeDetection(detectionId),
    getRealtimeActions({ providerId, detectionId, pageSize: 20 }),
  ]);
  return {
    detection: detection.ok ? detection.data : null,
    actions: actions.ok ? actions.data.items : [],
  };
};

const loadReal = async ({
  providerId,
  searchParams,
}: RealtimeTabProps): Promise<
  RealtimeResult<{ page: RealtimePage<RealtimeDetection> } & SelectedDetection>
> => {
  const detections = await getRealtimeDetections({
    providerId,
    statusIn: listParam(searchParams, STATUS_FILTER),
    severityIn: listParam(searchParams, SEVERITY_FILTER),
    ruleId: firstParam(searchParams, RULE_FILTER),
    page: pageParam(searchParams),
    pageSize: pageSizeParam(searchParams),
  });
  if (!detections.ok) return detections;
  const selected = await loadSelected(
    providerId,
    firstParam(searchParams, REALTIME_PARAM.DETECTION),
    detections.data,
  );
  return { ok: true, data: { page: detections.data, ...selected } };
};

export async function DetectionsTab(props: RealtimeTabProps) {
  const result = props.demo ? await loadDemo(props) : await loadReal(props);
  if (!result.ok) return <RealtimePanelError failure={result} />;
  const { page, detection, actions } = result.data;

  return (
    <DetectionsTable
      providerId={props.providerId}
      detections={page.items}
      metadata={toTableMetadata(page)}
      selected={detection}
      selectedActions={actions}
      filtered={
        listParam(props.searchParams, STATUS_FILTER).length > 0 ||
        listParam(props.searchParams, SEVERITY_FILTER).length > 0 ||
        Boolean(firstParam(props.searchParams, RULE_FILTER))
      }
    />
  );
}

export function DetectionsTabSkeleton() {
  return (
    <div className="flex flex-col gap-4" aria-hidden="true">
      <div className="flex gap-2">
        <Skeleton className="h-9 w-56 rounded-lg" />
        <Skeleton className="h-9 w-56 rounded-lg" />
      </div>
      <Skeleton className="h-[480px] w-full rounded-xl" />
    </div>
  );
}
