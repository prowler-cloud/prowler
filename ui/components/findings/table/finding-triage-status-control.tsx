"use client";

import { useState } from "react";

import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectStatusDot,
  type SelectStatusTone,
  SelectTrigger,
} from "@/components/shadcn/select/select";
import {
  FINDING_TRIAGE_MANUAL_STATUS_VALUES,
  FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageManualStatus,
  type FindingTriageStatus,
  type FindingTriageSummary,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

export type FindingTriageUpdateHandler = (
  input: UpdateFindingTriageInput,
) => void | Promise<void>;

const TRIAGE_STATUS_TONE = {
  open: "warning",
  under_review: "attention",
  remediating: "info",
  resolved: "success",
  risk_accepted: "risk",
  false_positive: "risk",
  reopened: "warning",
} as const satisfies Record<FindingTriageStatus, SelectStatusTone>;

export const isManualStatus = (
  status: FindingTriageStatus,
): status is FindingTriageManualStatus => {
  return FINDING_TRIAGE_MANUAL_STATUS_VALUES.some((value) => value === status);
};

export const isMutelistShortcutStatus = (
  status: FindingTriageStatus,
): boolean => {
  return FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES.some(
    (value) => value === status,
  );
};

const MUTELIST_CONFIRMATION_TITLE = "Mute finding?";
const MUTELIST_CONFIRMATION_COPY =
  "Changing to this triage status will mute the finding.";

export function FindingTriageStatusDot({
  status,
}: {
  status: FindingTriageStatus;
}) {
  return <SelectStatusDot tone={TRIAGE_STATUS_TONE[status]} />;
}

function TriageStatusPicker({
  disabled,
  value,
  onValueChange,
}: {
  disabled: boolean;
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
        size="status-table"
        iconSize="sm"
        variant="status"
        tone={TRIAGE_STATUS_TONE[value]}
      >
        <span className="truncate">{FINDING_TRIAGE_STATUS_LABELS[value]}</span>
      </SelectTrigger>
      <SelectContent>
        {FINDING_TRIAGE_MANUAL_STATUS_VALUES.map((status) => (
          <SelectItem
            key={status}
            value={status}
            tone={TRIAGE_STATUS_TONE[status]}
          >
            <SelectStatusDot tone={TRIAGE_STATUS_TONE[status]} />
            <span>{FINDING_TRIAGE_STATUS_LABELS[status]}</span>
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
        disabled={!triage.canEdit}
        value={props.value}
        onValueChange={props.onValueChange}
      />
    );
  }

  const canMutateFromTable =
    triage.canEdit && Boolean(props.onTriageUpdateAction) && !isTableUpdating;

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
        origin: "table",
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
      <TriageStatusPicker
        disabled={!canMutateFromTable}
        value={triage.status}
        onValueChange={handleTableValueChange}
      />
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
        description={MUTELIST_CONFIRMATION_COPY}
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
