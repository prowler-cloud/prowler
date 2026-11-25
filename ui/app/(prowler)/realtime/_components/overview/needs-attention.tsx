import { CheckCircle2 } from "lucide-react";
import Link from "next/link";

import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import {
  ATTENTION_ITEM_KIND,
  type AttentionItem,
} from "@/app/(prowler)/realtime/_lib/attention";
import {
  actionStatusBadge,
  detectionStatusBadge,
  formatRelativeTime,
} from "@/app/(prowler)/realtime/_lib/display";
import {
  REALTIME_PARAM,
  REALTIME_TAB,
  realtimeHref,
} from "@/app/(prowler)/realtime/_lib/routes";
import { Button, Card, CardContent } from "@/components/shadcn";
import {
  type Severity,
  SeverityBadge,
} from "@/components/shadcn/table/severity-badge";

interface NeedsAttentionProps {
  providerId: string;
  items: AttentionItem[];
}

const reviewHref = (providerId: string, item: AttentionItem) =>
  item.kind === ATTENTION_ITEM_KIND.DETECTION
    ? realtimeHref(providerId, REALTIME_TAB.DETECTIONS, {
        [REALTIME_PARAM.DETECTION]: item.id,
      })
    : realtimeHref(providerId, REALTIME_TAB.REMEDIATION, {
        [REALTIME_PARAM.ACTION]: item.id,
      });

/** Violations and failed responses, each one click from its detail. */
export function NeedsAttention({ providerId, items }: NeedsAttentionProps) {
  return (
    <Card variant="base" padding="lg" className="h-full">
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex flex-col gap-1">
            <h3 className="text-text-neutral-primary text-base font-semibold">
              Needs attention
            </h3>
            <p className="text-text-neutral-tertiary text-sm">
              Confirmed violations and responses that did not finish.
            </p>
          </div>
          <Button variant="link" size="link-sm" asChild>
            <Link href={realtimeHref(providerId, REALTIME_TAB.DETECTIONS)}>
              View all detections
            </Link>
          </Button>
        </div>
        {items.length === 0 ? (
          <div className="text-text-neutral-tertiary flex items-center gap-2 py-6 text-sm">
            <CheckCircle2 className="text-text-success-primary size-4" />
            Nothing needs attention right now.
          </div>
        ) : (
          <ul className="flex flex-col">
            {items.map((item) => (
              <li
                key={`${item.kind}:${item.id}`}
                className="border-border-neutral-secondary grid grid-cols-1 items-center gap-2 border-t py-3 md:grid-cols-[96px_minmax(0,1fr)_auto_auto] md:gap-3"
              >
                <SeverityBadge severity={item.severity as Severity} />
                <div className="flex min-w-0 flex-col gap-0.5">
                  <span className="text-text-neutral-primary truncate text-sm font-medium">
                    {item.title}
                  </span>
                  <span className="text-text-neutral-tertiary truncate font-mono text-xs">
                    {item.context} · {formatRelativeTime(item.at)}
                  </span>
                </div>
                <RealtimeBadge
                  descriptor={
                    item.kind === ATTENTION_ITEM_KIND.DETECTION
                      ? detectionStatusBadge(item.status)
                      : actionStatusBadge(item.status)
                  }
                />
                <Button variant="outline" size="sm" asChild>
                  <Link href={reviewHref(providerId, item)}>Review</Link>
                </Button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
