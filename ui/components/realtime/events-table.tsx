import { DetectionStatusBadge } from "@/components/realtime/realtime-badges";
import { PanelEmpty } from "@/components/realtime/realtime-states";
import { Badge } from "@/components/shadcn/badge/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";
import { formatDateTime } from "@/lib/realtime/display";
import type { RealtimeEvent } from "@/types/realtime";

/** The short name of an ARN: `arn:aws:iam::123:user/ana` to `user/ana`. */
export const actorLabel = (event: RealtimeEvent): string => {
  if (event.user_arn) {
    const resource = event.user_arn.split(":").slice(5).join(":");
    return resource || event.user_arn;
  }
  return event.user_type || "Unknown";
};

export function EventsTable({
  events,
  writesOnly,
}: {
  events: RealtimeEvent[];
  writesOnly: boolean;
}) {
  if (events.length === 0) {
    return (
      <PanelEmpty
        title="No events in the last 24 hours"
        description={
          writesOnly
            ? "Nothing that changes your account arrived yet. Show read calls too, or check the feed now."
            : "Nothing arrived yet. Check the feed now, or confirm the feed is set up."
        }
      />
    );
  }

  return (
    <Table aria-label="Recent CloudTrail events">
      <TableHeader>
        <TableRow>
          <TableHead>Time</TableHead>
          <TableHead>Event</TableHead>
          <TableHead>Region</TableHead>
          <TableHead>Actor</TableHead>
          <TableHead>Source IP</TableHead>
          <TableHead>Detection</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((event) => (
          <TableRow key={event.id}>
            <TableCell className="text-text-neutral-secondary text-xs whitespace-nowrap tabular-nums">
              {formatDateTime(event.event_time)}
            </TableCell>
            <TableCell>
              <div className="flex flex-col">
                <span className="text-text-neutral-primary font-medium">
                  {event.event_name}
                </span>
                <span className="text-text-neutral-tertiary text-xs">
                  {event.event_source}
                  {event.read_only ? " (read)" : ""}
                </span>
                {event.error_code && (
                  <span className="text-text-error-primary text-xs">
                    {event.error_code}
                  </span>
                )}
              </div>
            </TableCell>
            <TableCell className="text-text-neutral-secondary">
              {event.region || "global"}
            </TableCell>
            <TableCell className="max-w-56">
              <span
                className="text-text-neutral-secondary block truncate"
                title={event.user_arn || undefined}
              >
                {actorLabel(event)}
              </span>
            </TableCell>
            <TableCell className="text-text-neutral-secondary font-mono text-xs">
              {event.source_ip || "-"}
            </TableCell>
            <TableCell>
              {event.detection_status ? (
                <div className="flex flex-col items-start gap-1">
                  <DetectionStatusBadge status={event.detection_status} />
                  {event.rule_id && (
                    <span className="text-text-neutral-tertiary text-xs">
                      {event.rule_id}
                    </span>
                  )}
                </div>
              ) : (
                <Badge variant="outline">None</Badge>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
