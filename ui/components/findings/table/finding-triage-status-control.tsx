"use client";

import { type ComponentProps, useState } from "react";

import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
} from "@/components/shadcn/select/select";
import { cn } from "@/lib/utils";
import {
  FINDING_TRIAGE_MANUAL_STATUS_VALUES,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageManualStatus,
  type FindingTriageStatus,
  type FindingTriageSummary,
  getFindingTriageMuteInfoCopy,
  isManualStatus,
  isMutelistShortcutStatus,
  isTriageStatusLocked,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

export type FindingTriageUpdateHandler = (
  input: UpdateFindingTriageInput,
) => void | Promise<void>;

type TriageStatusPickerSize = NonNullable<
  ComponentProps<typeof SelectTrigger>["size"]
>;

export const TRIAGE_STATUS_TEXT_CLASS = {
  open: "text-text-error-primary",
  under_review: "text-text-warning-primary",
  remediating: "text-bg-data-info",
  resolved: "text-bg-pass",
  risk_accepted: "text-bg-pass",
  false_positive: "text-text-neutral-secondary",
  reopened: "text-text-error-primary",
} as const satisfies Record<FindingTriageStatus, string>;

const MUTELIST_CONFIRMATION_TITLE = "Mute finding?";

function TriageStatusPicker({
  disabled,
  size = "sm",
  value,
  onValueChange,
}: {
  disabled: boolean;
  size?: TriageStatusPickerSize;
  value: FindingTriageStatus;
  onValueChange: (status: FindingTriageManualStatus) => void;
}) {
  return (
    <Select
      value={value}
      disabled={disabled}
      onValueChange={(nextStatus) => {
        if (isManualStatus(nextStatus as FindingTriageStatus)) {
          onValueChange(nextStatus as FindingTriageManualStatus);
        }
      }}
    >
      <SelectTrigger
        aria-label="Triage status"
        disabled={disabled}
        size={size}
        iconSize="sm"
      >
        <span className={cn("truncate", TRIAGE_STATUS_TEXT_CLASS[value])}>
          {FINDING_TRIAGE_STATUS_LABELS[value]}
        </span>
      </SelectTrigger>
      <SelectContent>
        {FINDING_TRIAGE_MANUAL_STATUS_VALUES.map((status) => (
          <SelectItem key={status} value={status}>
            <span className={cn("truncate", TRIAGE_STATUS_TEXT_CLASS[status])}>
              {FINDING_TRIAGE_STATUS_LABELS[status]}
            </span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

type TableStatusControlProps = {
  origin: typeof FINDING_TRIAGE_ORIGIN.TABLE;
  triage: FindingTriageSummary;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
};

type ModalStatusControlProps = {
  origin: typeof FINDING_TRIAGE_ORIGIN.MODAL;
  triage: FindingTriageSummary;
  value: FindingTriageStatus;
  onValueChange: (status: FindingTriageManualStatus) => void;
};

type FindingTriageStatusControlProps =
  | TableStatusControlProps
  | ModalStatusControlProps;

export function FindingTriageStatusControl(
  props: FindingTriageStatusControlProps,
) {
  const [tableUpdateError, setTableUpdateError] = useState<string | null>(null);
  const [isTableUpdating, setIsTableUpdating] = useState(false);
  const [pendingShortcutStatus, setPendingShortcutStatus] =
    useState<FindingTriageManualStatus | null>(null);
  const triage = props.triage;

  if (props.origin === FINDING_TRIAGE_ORIGIN.MODAL) {
    return (
      <TriageStatusPicker
        disabled={!triage.canEdit || isTriageStatusLocked(triage.status)}
        value={props.value}
        onValueChange={props.onValueChange}
      />
    );
  }

  const canMutateFromTable =
    triage.canEdit &&
    Boolean(props.onTriageUpdateAction) &&
    !isTableUpdating &&
    !isTriageStatusLocked(triage.status);

  const applyTableStatus = async (status: FindingTriageManualStatus) => {
    if (!props.onTriageUpdateAction || status === triage.status) {
      return;
    }

    setTableUpdateError(null);
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
    } catch {
      setTableUpdateError("Could not update triage status.");
    } finally {
      setIsTableUpdating(false);
    }
  };

  const shouldConfirmMute = (status: FindingTriageManualStatus) =>
    !triage.isMuted &&
    isMutelistShortcutStatus(status) &&
    !isMutelistShortcutStatus(triage.status);

  const handleTableValueChange = (status: FindingTriageManualStatus) => {
    if (!props.onTriageUpdateAction || status === triage.status) {
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
          onValueChange={handleTableValueChange}
        />
      </div>
      {tableUpdateError && (
        <span className="sr-only" role="alert">
          {tableUpdateError}
        </span>
      )}
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
