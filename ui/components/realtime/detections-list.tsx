"use client";

import { useState } from "react";

import { getRealtimeDemo, getRealtimeDetections } from "@/actions/realtime";
import { DetectionStatusBadge } from "@/components/realtime/realtime-badges";
import { RealtimePager } from "@/components/realtime/realtime-pager";
import { RealtimeSeverity } from "@/components/realtime/realtime-severity";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelEmpty,
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Badge } from "@/components/shadcn/badge/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";
import {
  detectionStatusBadge,
  formatDateTime,
  isDriftDetection,
} from "@/lib/realtime/display";
import {
  REALTIME_DETECTION_STATUS,
  type RealtimeDetection,
  type RealtimePage,
} from "@/types/realtime";

const REFRESH_MS = 20_000;
const ALL = "all";

export function DetectionsTable({
  detections,
}: {
  detections: RealtimeDetection[];
}) {
  if (detections.length === 0) {
    return (
      <PanelEmpty
        title="No detections"
        description="When a risky API call is seen, Prowler Realtime checks the resource it touched and records the verdict here."
      />
    );
  }
  return (
    <Table aria-label="Detections">
      <TableHeader>
        <TableRow>
          <TableHead>When</TableHead>
          <TableHead>Detection</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Actor and resource</TableHead>
          <TableHead>Verdict</TableHead>
          <TableHead>Requirements</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {detections.map((detection) => (
          <TableRow key={detection.id}>
            <TableCell className="text-text-neutral-secondary text-xs whitespace-nowrap tabular-nums">
              {formatDateTime(detection.event_time)}
            </TableCell>
            <TableCell className="max-w-64">
              <div className="flex flex-col">
                <span className="text-text-neutral-primary">
                  {detection.title}
                </span>
                {isDriftDetection(detection) && (
                  <Badge variant="warning" size="sm" className="my-0.5">
                    Compliance drift
                  </Badge>
                )}
                <code className="text-text-neutral-tertiary text-xs">
                  {detection.rule_id}
                </code>
              </div>
            </TableCell>
            <TableCell>
              <RealtimeSeverity severity={detection.severity} />
            </TableCell>
            <TableCell className="max-w-64">
              <span
                className="text-text-neutral-secondary block truncate text-xs"
                title={detection.actor}
              >
                {detection.actor || "Unknown actor"}
              </span>
              <span
                className="text-text-neutral-tertiary block truncate text-xs"
                title={detection.resource}
              >
                {detection.resource || "No single target"}
                {detection.region ? ` (${detection.region})` : ""}
              </span>
            </TableCell>
            <TableCell className="max-w-64">
              <div className="flex flex-col items-start gap-1">
                <DetectionStatusBadge status={detection.status} />
                {detection.note && (
                  <span className="text-text-neutral-tertiary text-xs">
                    {detection.note}
                  </span>
                )}
              </div>
            </TableCell>
            <TableCell className="max-w-56">
              <div className="flex flex-wrap gap-1">
                {detection.requirements.length > 0 ? (
                  detection.requirements.map((requirement) => (
                    <Badge key={requirement} variant="tag" size="sm">
                      {requirement}
                    </Badge>
                  ))
                ) : (
                  <span className="text-text-neutral-tertiary text-xs">-</span>
                )}
              </div>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function DetectionsList({
  providerId,
  demo = false,
}: {
  providerId: string;
  demo?: boolean;
}) {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState(ALL);

  // The sample is one fixed page: the verdict filter is applied here.
  const detections = useRealtimeResource<RealtimePage<RealtimeDetection>>(
    async () => {
      if (!demo) {
        return getRealtimeDetections({
          providerId,
          page,
          statusIn: status === ALL ? undefined : [status],
        });
      }
      const result = await getRealtimeDemo("detections");
      if (!result.ok || status === ALL) return result;
      const items = result.data.items.filter((item) => item.status === status);
      return {
        ok: true as const,
        data: { items, page: 1, pages: 1, count: items.length },
      };
    },
    demo
      ? `demo:detections:${status}`
      : `detections:${providerId}:${page}:${status}`,
    { intervalMs: demo ? undefined : REFRESH_MS },
  );

  return (
    <RealtimeSection
      title="Detections"
      description="Risky API calls Prowler Realtime saw, and what Prowler found when it checked the resource."
      action={
        <Select
          value={status}
          onValueChange={(value) => {
            setStatus(value || ALL);
            setPage(1);
          }}
        >
          <SelectTrigger size="xs" aria-label="Filter detections by verdict">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All verdicts</SelectItem>
            {Object.values(REALTIME_DETECTION_STATUS).map((value) => (
              <SelectItem key={value} value={value}>
                {detectionStatusBadge(value).label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      }
    >
      {detections.loading ? (
        <PanelLoading label="Loading detections" />
      ) : detections.failure ? (
        <PanelFailure
          failure={detections.failure}
          onRetry={detections.reload}
          subject="the detections"
        />
      ) : detections.data ? (
        <div className="flex flex-col gap-3">
          <DetectionsTable detections={detections.data.items} />
          <RealtimePager
            page={detections.data.page}
            pages={detections.data.pages}
            count={detections.data.count}
            onPageChange={setPage}
          />
        </div>
      ) : null}
    </RealtimeSection>
  );
}
