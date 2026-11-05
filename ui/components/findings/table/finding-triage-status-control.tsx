"use client";

import { useState } from "react";

import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/shadcn/toast/use-toast";
import { TriageStatusPicker } from "@/components/shared/triage/triage-status-picker";
import { usageLimitToastAction } from "@/components/shared/usage-limit-message";
import { USAGE_LIMIT_MESSAGE, UsageLimitError } from "@/lib/action-errors";
import { FINDING_STATUS } from "@/types/components";
import {
  FINDING_TRIAGE_MANUAL_STATUS_VALUES,
  FINDING_TRIAGE_MODAL_STATUS_VALUES,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_STATUS,
  type FindingTriageManualStatus,
  type FindingTriageModalStatus,
  type FindingTriageSummary,
  type FindingTriageUpdateHandler,
  getFindingTriageMuteInfoCopy,
  isMutelistShortcutStatus,
  isTriageStatusLocked,
} from "@/types/findings-triage";

const MUTELIST_CONFIRMATION_TITLE = "Mute finding?";

type TableStatusControlProps = {
  origin: typeof FINDING_TRIAGE_ORIGIN.TABLE;
  triage: FindingTriageSummary;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onManualPassRequest?: () => void;
};

type ModalStatusControlProps = {
  origin: typeof FINDING_TRIAGE_ORIGIN.MODAL;
  triage: FindingTriageSummary;
  value: FindingTriageModalStatus;
  includeManualPass: boolean;
  onValueChange: (status: FindingTriageModalStatus) => void;
};

type FindingTriageStatusControlProps =
  | TableStatusControlProps
  | ModalStatusControlProps;

export function FindingTriageStatusControl(
  props: FindingTriageStatusControlProps,
) {
  const { toast } = useToast();
  const [isTableUpdating, setIsTableUpdating] = useState(false);
  const [pendingShortcutStatus, setPendingShortcutStatus] =
    useState<FindingTriageManualStatus | null>(null);
  const triage = props.triage;

  if (props.origin === FINDING_TRIAGE_ORIGIN.MODAL) {
    return (
      <TriageStatusPicker
        disabled={!triage.canEdit || isTriageStatusLocked(triage.status)}
        value={props.value}
        statusValues={
          props.includeManualPass
            ? FINDING_TRIAGE_MODAL_STATUS_VALUES
            : FINDING_TRIAGE_MANUAL_STATUS_VALUES
        }
        onValueChange={props.onValueChange}
      />
    );
  }

  const canMutateFromTable =
    triage.canEdit &&
    Boolean(props.onTriageUpdateAction) &&
    !isTableUpdating &&
    !isTriageStatusLocked(triage.status);
  const isAuthoritativeManual =
    triage.rawFindingStatus === FINDING_STATUS.MANUAL;
  const includeManualPass =
    isAuthoritativeManual && Boolean(props.onManualPassRequest);

  const applyTableStatus = async (status: FindingTriageManualStatus) => {
    if (!props.onTriageUpdateAction || status === triage.status) {
      return;
    }

    setIsTableUpdating(true);

    try {
      await props.onTriageUpdateAction({
        findingId: triage.findingId,
        findingUid: triage.findingUid,
        triageId: triage.triageId,
        notesCount: triage.notesCount,
        status,
        previousStatus: triage.status,
        isMuted: triage.isMuted,
      });
    } catch (error) {
      const isUsageLimited = error instanceof UsageLimitError;
      toast({
        variant: "destructive",
        title: "Could not update triage status.",
        description: isUsageLimited ? USAGE_LIMIT_MESSAGE : "Please try again.",
        ...(isUsageLimited && { action: usageLimitToastAction() }),
      });
    } finally {
      setIsTableUpdating(false);
    }
  };

  const shouldConfirmMute = (status: FindingTriageManualStatus) =>
    !triage.isMuted &&
    isMutelistShortcutStatus(status) &&
    !isMutelistShortcutStatus(triage.status);

  const handleTableValueChange = (status: FindingTriageModalStatus) => {
    if (!props.onTriageUpdateAction || status === triage.status) {
      return;
    }

    if (status === FINDING_TRIAGE_STATUS.RESOLVED) {
      props.onManualPassRequest?.();
      return;
    }

    if (shouldConfirmMute(status)) {
      setPendingShortcutStatus(status);
      return;
    }

    void applyTableStatus(status);
  };

  return (
    <>
      <div className="w-32">
        <TriageStatusPicker
          disabled={!canMutateFromTable}
          size="xs"
          value={triage.status}
          statusValues={
            includeManualPass
              ? FINDING_TRIAGE_MODAL_STATUS_VALUES
              : FINDING_TRIAGE_MANUAL_STATUS_VALUES
          }
          showManualPassTooltip={includeManualPass}
          onValueChange={handleTableValueChange}
        />
      </div>
      <Modal
        open={pendingShortcutStatus !== null}
        onOpenChange={(open) => {
          if (!open) {
            setPendingShortcutStatus(null);
          }
        }}
        title={MUTELIST_CONFIRMATION_TITLE}
        description={
          pendingShortcutStatus
            ? getFindingTriageMuteInfoCopy(pendingShortcutStatus)
            : undefined
        }
        size="sm"
      >
        <div className="flex justify-end gap-2 pt-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => setPendingShortcutStatus(null)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => {
              const status = pendingShortcutStatus;
              setPendingShortcutStatus(null);
              if (status) {
                void applyTableStatus(status);
              }
            }}
          >
            Mute finding
          </Button>
        </div>
      </Modal>
    </>
  );
}
