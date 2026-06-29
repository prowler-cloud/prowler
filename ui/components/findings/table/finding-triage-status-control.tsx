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

const MUTELIST_INFO_TITLE = "Mutelist information";
const MUTELIST_INFO_COPY =
  "This finding will be muted through the existing Mutelist flow.";

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
  const [selectedStatus, setSelectedStatus] = useState(props.triage.status);
  const [pendingMutelistStatus, setPendingMutelistStatus] =
    useState<FindingTriageManualStatus | null>(null);
  const [tableUpdateError, setTableUpdateError] = useState<string | null>(null);
  const [isTableUpdating, setIsTableUpdating] = useState(false);
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
    if (!props.onTriageUpdateAction) {
      return;
    }

    const previousStatus = selectedStatus;
    setTableUpdateError(null);
    setIsTableUpdating(true);
    setSelectedStatus(status);

    try {
      await props.onTriageUpdateAction({
        findingId: triage.findingId,
        findingUid: triage.findingUid,
        triageId: triage.triageId,
        notesCount: triage.notesCount,
        status,
        origin: "table",
      });
    } catch {
      setSelectedStatus(previousStatus);
      setTableUpdateError("Could not update triage status.");
    } finally {
      setIsTableUpdating(false);
    }
  };

  const handleTableValueChange = (status: FindingTriageManualStatus) => {
    if (!props.onTriageUpdateAction) {
      return;
    }

    if (isMutelistShortcutStatus(status)) {
      setPendingMutelistStatus(status);
      return;
    }

    void applyTableStatus(status);
  };

  const handleMutelistOpenChange = (open: boolean) => {
    if (!open) {
      setPendingMutelistStatus(null);
    }
  };

  const handleConfirmMutelistStatus = () => {
    if (!pendingMutelistStatus) {
      return;
    }

    void applyTableStatus(pendingMutelistStatus);
    setPendingMutelistStatus(null);
  };

  return (
    <>
      <TriageStatusPicker
        disabled={!canMutateFromTable}
        value={selectedStatus}
        onValueChange={handleTableValueChange}
      />
      {tableUpdateError && (
        <span className="sr-only" role="alert">
          {tableUpdateError}
        </span>
      )}
      <Modal
        open={pendingMutelistStatus !== null}
        onOpenChange={handleMutelistOpenChange}
        title={MUTELIST_INFO_TITLE}
        size="sm"
      >
        <div className="flex flex-col gap-6">
          <p className="text-text-neutral-secondary text-sm">
            {MUTELIST_INFO_COPY}
          </p>
          <div className="flex justify-end gap-3">
            <Button
              type="button"
              variant="outline"
              size="lg"
              onClick={() => setPendingMutelistStatus(null)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              size="lg"
              onClick={handleConfirmMutelistStatus}
            >
              Accept
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
