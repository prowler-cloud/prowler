"use client";

import Link from "next/link";

import { RealtimeBadge } from "@/app/(prowler)/realtime/_components/shared/realtime-badge";
import {
  actionKindLabel,
  actionStatusBadge,
  asSeverity,
  formatDateTime,
} from "@/app/(prowler)/realtime/_lib/display";
import {
  checkFindingsHref,
  REALTIME_PARAM,
  REALTIME_TAB,
  realtimeHref,
} from "@/app/(prowler)/realtime/_lib/routes";
import type { RealtimeAction } from "@/app/(prowler)/realtime/_types";
import { Button, InfoField } from "@/components/shadcn";
import { SeverityBadge } from "@/components/shadcn/table";

import { ActionResult } from "./action-result";
import { RevertActionButton } from "./revert-action-button";

interface ActionDetailProps {
  providerId: string;
  action: RealtimeAction | null;
  canWrite: boolean;
  demo: boolean;
}

/** One remediation action in the side panel. */
export function ActionDetail({
  providerId,
  action,
  canWrite,
  demo,
}: ActionDetailProps) {
  if (!action) {
    return (
      <p className="text-text-neutral-tertiary p-4 text-sm">
        This action is no longer available.
      </p>
    );
  }
  const severity = asSeverity(action.severity);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto p-4">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            {severity && <SeverityBadge severity={severity} />}
            <RealtimeBadge descriptor={actionStatusBadge(action.status)} />
          </div>
          <h3 className="text-text-neutral-primary text-lg font-semibold">
            {actionKindLabel(action.kind)}
          </h3>
          <p className="text-text-neutral-tertiary font-mono text-xs break-all">
            {action.check_id}
          </p>
        </div>
        <section className="flex flex-col gap-3">
          <InfoField label="When" variant="compact">
            {formatDateTime(action.inserted_at)}
          </InfoField>
          <InfoField label="Resource" variant="compact">
            <span className="font-mono text-xs break-all">
              {[action.resource_uid, action.region].filter(Boolean).join(" · ")}
            </span>
          </InfoField>
          {action.branch && (
            <InfoField label="Branch" variant="compact">
              <span className="font-mono text-xs break-all">
                {action.branch}
              </span>
            </InfoField>
          )}
          <InfoField label="Result" variant="compact">
            <ActionResult action={action} providerId={providerId} />
          </InfoField>
        </section>
        {action.revertible && (
          <div>
            <RevertActionButton
              action={action}
              canWrite={canWrite}
              demo={demo}
            />
          </div>
        )}
      </div>
      <div className="border-border-neutral-secondary flex flex-wrap gap-2 border-t p-4">
        {action.check_id && (
          <Button asChild>
            <Link href={checkFindingsHref(action.check_id)}>View findings</Link>
          </Button>
        )}
        {action.detection_id && (
          <Button variant="outline" asChild>
            <Link
              href={realtimeHref(providerId, REALTIME_TAB.DETECTIONS, {
                [REALTIME_PARAM.DETECTION]: action.detection_id,
              })}
            >
              Open detection
            </Link>
          </Button>
        )}
      </div>
    </div>
  );
}
