import Link from "next/link";

import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import {
  actionKindLabel,
  actionStatusBadge,
  asSeverity,
  detectionStatusBadge,
  formatDateTime,
  safeExternalUrl,
} from "@/app/(prowler)/realtime/_lib/display";
import {
  checkFindingsHref,
  REALTIME_TAB,
  realtimeHref,
} from "@/app/(prowler)/realtime/_lib/routes";
import type {
  RealtimeAction,
  RealtimeDetection,
} from "@/app/(prowler)/realtime/_types";
import { Badge, Button, Card, InfoField } from "@/components/shadcn";
import { SeverityBadge } from "@/components/shadcn/table";

interface DetectionDetailProps {
  providerId: string;
  detection: RealtimeDetection | null;
  actions: RealtimeAction[];
}

/** One detection in the side panel: what happened, the verdict and the response. */
export function DetectionDetail({
  providerId,
  detection,
  actions,
}: DetectionDetailProps) {
  if (!detection) {
    return (
      <p className="text-text-neutral-tertiary p-4 text-sm">
        This detection is no longer available.
      </p>
    );
  }
  const severity = asSeverity(detection.severity);
  const [firstCheck] = detection.check_ids;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto p-4">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            {severity && <SeverityBadge severity={severity} />}
            <RealtimeBadge
              descriptor={detectionStatusBadge(detection.status)}
            />
          </div>
          <h3 className="text-text-neutral-primary text-lg leading-snug font-semibold">
            {detection.title}
          </h3>
          <p className="text-text-neutral-tertiary text-xs">
            Rule <span className="font-mono">{detection.rule_id}</span>
            {detection.verified_at
              ? ` · verified ${formatDateTime(detection.verified_at)}`
              : " · waiting for verification"}
          </p>
        </div>

        <section className="flex flex-col gap-3">
          <h4 className="text-text-neutral-primary text-sm font-semibold">
            What happened
          </h4>
          <InfoField label="When" variant="compact">
            {formatDateTime(detection.event_time)}
          </InfoField>
          <InfoField label="Actor" variant="compact">
            <span className="font-mono text-xs break-all">
              {detection.actor || "Unknown"}
            </span>
          </InfoField>
          <InfoField label="Resource" variant="compact">
            <span className="font-mono text-xs break-all">
              {[detection.resource, detection.region]
                .filter(Boolean)
                .join(" · ")}
            </span>
          </InfoField>
          {detection.event_id && (
            <InfoField label="Event id" variant="compact">
              <span className="font-mono text-xs break-all">
                {detection.event_id}
              </span>
            </InfoField>
          )}
        </section>

        <Card variant="inner" className="gap-2">
          <h4 className="text-text-neutral-primary text-sm font-semibold">
            Verdict
          </h4>
          <p className="text-text-neutral-secondary text-sm">
            {detection.note || "Prowler has not checked the resource yet."}
          </p>
          {detection.check_ids.length > 0 && (
            <p className="text-text-neutral-tertiary font-mono text-xs break-all">
              {detection.check_ids.join(", ")}
            </p>
          )}
          {detection.requirements.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {detection.requirements.map((requirement) => (
                <Badge key={requirement} variant="tag">
                  {requirement}
                </Badge>
              ))}
            </div>
          )}
        </Card>

        <section className="flex flex-col gap-3">
          <h4 className="text-text-neutral-primary text-sm font-semibold">
            Response
          </h4>
          {actions.length === 0 ? (
            <p className="text-text-neutral-tertiary text-sm">
              No action was taken. The policy only alerts on this detection, or
              it is still being verified.
            </p>
          ) : (
            <ul className="flex flex-col gap-3">
              {actions.map((action) => {
                const prUrl = safeExternalUrl(action.pr_url);
                return (
                  <li key={action.id} className="flex flex-col gap-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-text-neutral-primary text-sm font-medium">
                        {actionKindLabel(action.kind)}
                      </span>
                      <RealtimeBadge
                        descriptor={actionStatusBadge(action.status)}
                      />
                    </div>
                    {action.summary && (
                      <p className="text-text-neutral-tertiary text-xs">
                        {action.summary}
                      </p>
                    )}
                    {prUrl && (
                      <Button
                        variant="link"
                        size="link-sm"
                        className="h-auto self-start p-0"
                        asChild
                      >
                        <a
                          href={prUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          View pull request
                        </a>
                      </Button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </div>

      <div className="border-border-neutral-secondary flex flex-wrap gap-2 border-t p-4">
        {firstCheck && (
          <Button asChild>
            <Link href={checkFindingsHref(firstCheck)}>View findings</Link>
          </Button>
        )}
        <Button variant="outline" asChild>
          <Link href={realtimeHref(providerId, REALTIME_TAB.STREAM)}>
            Open event stream
          </Link>
        </Button>
      </div>
    </div>
  );
}
