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
import { useToast } from "@/components/shadcn/toast/use-toast";
import { cn } from "@/lib/utils";
import { FINDING_STATUS } from "@/types/components";
import {
  FINDING_TRIAGE_MANUAL_STATUS_VALUES,
  FINDING_TRIAGE_MODAL_STATUS_VALUES,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_STATUS,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageManualStatus,
  type FindingTriageModalStatus,
  type FindingTriageStatus,
  type FindingTriageSummary,
  type FindingTriageUpdateHandler,
  getFindingTriageMuteInfoCopy,
  isMutelistShortcutStatus,
  isTriageStatusLocked,
} from "@/types/findings-triage";

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
export const MANUAL_PASS_NOTE_REQUIRED_COPY =
  "Add a Triage Note explaining why this finding passes.";

function TriageStatusPicker({
  disabled,
  size = "sm",
  value,
  statusValues,
  showManualPassTooltip = false,
  onValueChange,
}: {
  disabled: boolean;
  size?: TriageStatusPickerSize;
  value: FindingTriageStatus;
  statusValues: readonly FindingTriageModalStatus[];
  showManualPassTooltip?: boolean;
  onValueChange: (status: FindingTriageModalStatus) => void;
}) {
  return (
    <Select
      value={value}
      disabled={disabled}
      onValueChange={(nextStatus) => {
        if (statusValues.includes(nextStatus as FindingTriageModalStatus)) {
          onValueChange(nextStatus as FindingTriageModalStatus);
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
        {statusValues.map((status) => {
          const shouldExplainManualPass =
            showManualPassTooltip && status === FINDING_TRIAGE_STATUS.RESOLVED;
          return (
            <SelectItem
              key={status}
              value={status}
              aria-label={FINDING_TRIAGE_STATUS_LABELS[status]}
            >
              <span
                className={cn("truncate", TRIAGE_STATUS_TEXT_CLASS[status])}
              >
                {FINDING_TRIAGE_STATUS_LABELS[status]}
              </span>
              {shouldExplainManualPass && (
                <span
                  className="text-text-neutral-secondary text-xs font-normal normal-case"
                  aria-hidden="true"
                >
                  {MANUAL_PASS_NOTE_REQUIRED_COPY}
                </span>
              )}
            </SelectItem>
          );
        })}
      </SelectContent>
    </Select>
  );
}

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
    } catch {
      toast({
        variant: "destructive",
        title: "Could not update triage status.",
        description: "Please try again.",
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
