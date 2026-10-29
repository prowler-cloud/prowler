"use client";

import { useState } from "react";

import {
  getRealtimeActions,
  getRealtimeDemo,
  revertRealtimeAction,
} from "@/actions/realtime";
import { DemoDisabled, useIsDemo } from "@/components/realtime/demo-context";
import { ActionStatusBadge } from "@/components/realtime/realtime-badges";
import { RealtimePager } from "@/components/realtime/realtime-pager";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelEmpty,
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";
import { useToast } from "@/components/shadcn/toast";
import {
  formatDateTime,
  humanize,
  isLighthouseAction,
  safeExternalUrl,
} from "@/lib/realtime/display";
import {
  REALTIME_ACTION_KIND,
  type RealtimeAction,
  type RealtimePage,
} from "@/types/realtime";

const REFRESH_MS = 20_000;

const KIND_LABELS: Record<string, string> = {
  [REALTIME_ACTION_KIND.SELF_FIX]: "Fix in the account",
  [REALTIME_ACTION_KIND.CODE]: "Change in code",
  [REALTIME_ACTION_KIND.PROPOSAL]: "Proposal",
};

export const actionKindLabel = (kind: string): string =>
  KIND_LABELS[kind] ?? humanize(kind);

interface RevertDialogProps {
  action: RealtimeAction | null;
  reverting: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function RevertDialog({
  action,
  reverting,
  onConfirm,
  onCancel,
}: RevertDialogProps) {
  return (
    <Modal
      open={action !== null}
      onOpenChange={(open) => {
        if (!open && !reverting) onCancel();
      }}
      title="Revert this change?"
      description="Prowler Realtime applies the exact inverse of the call it recorded for this fix. The compliance check will fail again for this resource."
      size="lg"
    >
      {action && (
        <div className="flex flex-col gap-4">
          <p className="text-text-neutral-secondary text-sm">
            {action.summary || action.check_id}
            {action.resource_uid ? ` (${action.resource_uid})` : ""}
          </p>
          <div className="flex justify-end gap-2">
            <Button variant="outline" disabled={reverting} onClick={onCancel}>
              Keep the fix
            </Button>
            <Button
              variant="destructive"
              disabled={reverting}
              onClick={onConfirm}
            >
              {reverting ? "Reverting…" : "Revert the change"}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

interface ActionsTableProps {
  actions: RealtimeAction[];
  canManage: boolean;
  onRevert: (action: RealtimeAction) => void;
  /** Sample rows: Revert is disabled. Defaults to the surrounding view. */
  demo?: boolean;
}

export function ActionsTable({
  actions,
  canManage,
  onRevert,
  demo: demoProp,
}: ActionsTableProps) {
  const inDemo = useIsDemo();
  const demo = demoProp ?? inDemo;
  if (actions.length === 0) {
    return (
      <PanelEmpty
        title="Prowler Realtime has not acted yet"
        description="Fixes and proposals appear here, each with the evidence and, when possible, a way to undo it."
      />
    );
  }
  return (
    <Table aria-label="Prowler Realtime actions">
      <TableHeader>
        <TableRow>
          <TableHead>When</TableHead>
          <TableHead>What</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Resource</TableHead>
          <TableHead>Details</TableHead>
          <TableHead>
            <span className="sr-only">Actions</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {actions.map((action) => {
          const prUrl = action.pr_url ? safeExternalUrl(action.pr_url) : null;
          return (
            <TableRow key={action.id}>
              <TableCell className="text-text-neutral-secondary text-xs whitespace-nowrap tabular-nums">
                {formatDateTime(action.inserted_at)}
              </TableCell>
              <TableCell>
                <div className="flex flex-col">
                  <span className="text-text-neutral-primary">
                    {actionKindLabel(action.kind)}
                  </span>
                  <code className="text-text-neutral-tertiary text-xs break-all">
                    {action.check_id}
                  </code>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex flex-col items-start gap-1">
                  <ActionStatusBadge status={action.status} />
                  {isLighthouseAction(action) && (
                    <Badge variant="lighthouse" size="sm">
                      Lighthouse AI
                    </Badge>
                  )}
                </div>
              </TableCell>
              <TableCell className="max-w-56">
                <span
                  className="text-text-neutral-secondary block truncate"
                  title={action.resource_uid}
                >
                  {action.resource_uid || "-"}
                </span>
                {action.region && (
                  <span className="text-text-neutral-tertiary text-xs">
                    {action.region}
                  </span>
                )}
              </TableCell>
              <TableCell className="max-w-72">
                <p className="text-text-neutral-secondary text-xs">
                  {action.summary}
                </p>
                {prUrl ? (
                  <a
                    href={prUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-button-tertiary text-xs underline underline-offset-4"
                  >
                    View pull request
                  </a>
                ) : action.branch ? (
                  <span className="text-text-neutral-tertiary text-xs">
                    Branch {action.branch}
                  </span>
                ) : null}
              </TableCell>
              <TableCell>
                {action.revertible &&
                  (demo ? (
                    <DemoDisabled>
                      <Button variant="outline" size="sm" disabled>
                        Revert
                      </Button>
                    </DemoDisabled>
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={!canManage}
                      title={
                        canManage
                          ? undefined
                          : "Reverting needs the Manage Realtime permission"
                      }
                      onClick={() => onRevert(action)}
                    >
                      Revert
                    </Button>
                  ))}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

export function ActionsList({
  providerId,
  canManage,
  demo = false,
}: {
  providerId: string;
  canManage: boolean;
  demo?: boolean;
}) {
  const { toast } = useToast();
  const [page, setPage] = useState(1);
  const [pending, setPending] = useState<RealtimeAction | null>(null);
  const [reverting, setReverting] = useState(false);

  const actions = useRealtimeResource<RealtimePage<RealtimeAction>>(
    () =>
      demo
        ? getRealtimeDemo("actions")
        : getRealtimeActions({ providerId, page }),
    demo ? "demo:actions" : `actions:${providerId}:${page}`,
    { intervalMs: demo ? undefined : REFRESH_MS },
  );

  const confirmRevert = async () => {
    if (!pending || demo) return;
    setReverting(true);
    const result = await revertRealtimeAction(pending.id);
    setReverting(false);
    if (result.ok) {
      setPending(null);
      toast({ title: "Change reverted", description: result.data.summary });
      actions.reload();
    } else {
      setPending(null);
      toast({
        variant: "destructive",
        title: "Could not revert the change",
        description: result.error,
      });
    }
  };

  return (
    <RealtimeSection
      title="Actions"
      description="Everything Prowler Realtime changed or proposed. Automatic fixes keep the exact inverse call, so they can be undone."
    >
      {actions.loading ? (
        <PanelLoading label="Loading actions" />
      ) : actions.failure ? (
        <PanelFailure
          failure={actions.failure}
          onRetry={actions.reload}
          subject="the actions"
        />
      ) : actions.data ? (
        <div className="flex flex-col gap-3">
          <ActionsTable
            actions={actions.data.items}
            canManage={canManage}
            demo={demo}
            onRevert={setPending}
          />
          <RealtimePager
            page={actions.data.page}
            pages={actions.data.pages}
            count={actions.data.count}
            onPageChange={setPage}
          />
        </div>
      ) : null}
      <RevertDialog
        action={pending}
        reverting={reverting}
        onConfirm={() => void confirmRevert()}
        onCancel={() => setPending(null)}
      />
    </RealtimeSection>
  );
}
