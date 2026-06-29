"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Alert, AlertDescription, Button, Textarea } from "@/components/shadcn";
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
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_MANUAL_STATUS_VALUES,
  FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageDetail,
  type FindingTriageManualStatus,
  type FindingTriageStatus,
  type FindingTriageSummary,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";
import type { ProviderType } from "@/types/providers";

export interface FindingTriageContext {
  title: string;
  resource?: string;
  provider?: string;
  providerType?: ProviderType;
}

export type FindingTriageUpdateHandler = (
  input: UpdateFindingTriageInput,
) => void | Promise<void>;

interface FindingNoteModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  triage: FindingTriageDetail;
  findingContext: FindingTriageContext;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
}

const MUTELIST_INFO_TITLE = "Mutelist information";
const MUTELIST_INFO_COPY =
  "This finding will be muted through the existing Mutelist flow.";

const isManualStatus = (
  status: FindingTriageStatus,
): status is FindingTriageManualStatus => {
  return FINDING_TRIAGE_MANUAL_STATUS_VALUES.some((value) => value === status);
};

const isMutelistShortcutStatus = (status: FindingTriageStatus): boolean => {
  return FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES.some(
    (value) => value === status,
  );
};

const getVisibleStatusLabel = (status: FindingTriageStatus) => {
  return FINDING_TRIAGE_STATUS_LABELS[status];
};

const TRIAGE_STATUS_TONE = {
  open: "warning",
  under_review: "attention",
  remediating: "info",
  resolved: "success",
  risk_accepted: "risk",
  false_positive: "risk",
  reopened: "warning",
} as const satisfies Record<FindingTriageStatus, SelectStatusTone>;

function TriageStatusSelect({
  disabled,
  value,
  onValueChange,
  variant = "table",
}: {
  disabled: boolean;
  value: FindingTriageStatus;
  onValueChange: (status: FindingTriageManualStatus) => void;
  variant?: "table" | "modal";
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
        size={variant === "modal" ? "status-modal" : "status-table"}
        iconSize="sm"
        variant="status"
        tone={TRIAGE_STATUS_TONE[value]}
      >
        <span className="truncate">{getVisibleStatusLabel(value)}</span>
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

function FindingTriageStatusControl(props: FindingTriageStatusControlProps) {
  const [selectedStatus, setSelectedStatus] = useState(props.triage.status);
  const [pendingMutelistStatus, setPendingMutelistStatus] =
    useState<FindingTriageManualStatus | null>(null);
  const [tableUpdateError, setTableUpdateError] = useState<string | null>(null);
  const [isTableUpdating, setIsTableUpdating] = useState(false);
  const triage = props.triage;

  if (props.origin === FINDING_TRIAGE_ORIGIN.MODAL) {
    return (
      <TriageStatusSelect
        disabled={!triage.canEdit}
        value={props.value}
        variant="modal"
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

    if (!props.onTriageUpdateAction) {
      setPendingMutelistStatus(null);
      return;
    }

    void applyTableStatus(pendingMutelistStatus);
    setPendingMutelistStatus(null);
  };

  return (
    <>
      <TriageStatusSelect
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

export function FindingNoteModal({
  open,
  onOpenChange,
  triage,
  findingContext,
  onTriageUpdateAction,
}: FindingNoteModalProps) {
  const router = useRouter();
  // Local state needed: modal edits are buffered until the user chooses Update.
  const [selectedStatus, setSelectedStatus] = useState<FindingTriageStatus>(
    triage.status,
  );
  const [note, setNote] = useState(triage.noteBody);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const canSubmit =
    triage.canEdit && Boolean(onTriageUpdateAction) && !isSubmitting;
  const isCloudOnly =
    triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY;
  const shouldShowMutelistInfo =
    canSubmit && isMutelistShortcutStatus(selectedStatus);
  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!canSubmit) {
      if (isCloudOnly) {
        router.push(triage.billingHref);
      }
      return;
    }

    setSubmitError(null);
    setIsSubmitting(true);

    try {
      const trimmedNote = note.trim();
      const statusChanged = selectedStatus !== triage.status;
      const shouldCreateFirstNote =
        triage.notesCount === 0 && trimmedNote.length > 0;
      const shouldUpdateExistingNote =
        triage.notesCount > 0 &&
        triage.noteId !== null &&
        trimmedNote.length > 0 &&
        trimmedNote !== triage.noteBody;
      const shouldIncludeStatus =
        isManualStatus(selectedStatus) &&
        (statusChanged || shouldCreateFirstNote);

      if (
        !shouldIncludeStatus &&
        !shouldCreateFirstNote &&
        !shouldUpdateExistingNote
      ) {
        onOpenChange(false);
        return;
      }

      await onTriageUpdateAction?.({
        findingId: triage.findingId,
        findingUid: triage.findingUid,
        triageId: triage.triageId,
        notesCount: triage.notesCount,
        noteId: triage.noteId,
        ...(shouldIncludeStatus
          ? { status: selectedStatus as FindingTriageManualStatus }
          : {}),
        ...(shouldCreateFirstNote || shouldUpdateExistingNote
          ? { note: trimmedNote }
          : {}),
        origin: "modal",
      });
      onOpenChange(false);
    } catch {
      setSubmitError("Could not update the note. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handlePrimaryClick = () => {
    if (!canSubmit && isCloudOnly) {
      router.push(triage.billingHref);
    }
  };

  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Note" size="lg">
      <form className="flex flex-col gap-5" onSubmit={handleSubmit}>
        <div className="flex items-center gap-4">
          <div className="bg-bg-neutral-tertiary flex size-9 shrink-0 items-center justify-center rounded-lg">
            {findingContext.providerType ? (
              <ProviderTypeIcon type={findingContext.providerType} size={22} />
            ) : (
              <span className="text-text-neutral-secondary text-xs font-semibold">
                {findingContext.provider?.slice(0, 3).toUpperCase() ?? "—"}
              </span>
            )}
          </div>
          <div>
            <p className="text-text-neutral-primary text-sm font-semibold">
              {findingContext.title}
            </p>
            {(findingContext.resource || findingContext.provider) && (
              <p className="text-text-neutral-secondary mt-1 text-xs">
                {[findingContext.resource, findingContext.provider]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-text-neutral-primary text-sm font-semibold">
            Status:
          </span>
          <SelectStatusDot tone={TRIAGE_STATUS_TONE[selectedStatus]} />
          <FindingTriageStatusControl
            origin={FINDING_TRIAGE_ORIGIN.MODAL}
            triage={triage}
            value={selectedStatus}
            onValueChange={setSelectedStatus}
          />
        </div>

        {shouldShowMutelistInfo && (
          <Alert variant="warning">
            <AlertDescription>{MUTELIST_INFO_COPY}</AlertDescription>
          </Alert>
        )}

        {submitError && (
          <Alert variant="error">
            <AlertDescription>{submitError}</AlertDescription>
          </Alert>
        )}

        <div className="space-y-2">
          <div className="relative">
            <Textarea
              id="finding-triage-note"
              aria-label="Note text"
              value={note}
              maxLength={triage.maxNoteLength}
              disabled={!canSubmit}
              textareaSize="lg"
              className="min-h-48 pb-10"
              onChange={(event) => setNote(event.target.value)}
            />
            <p className="text-text-neutral-tertiary absolute right-4 bottom-4 text-xs">
              {note.length}/{triage.maxNoteLength}
            </p>
          </div>
          <p className="text-text-neutral-tertiary text-xs">
            {triage.privacyCopy}
          </p>
        </div>

        <div className="flex w-full justify-end gap-3">
          <Button
            type="button"
            variant="ghost"
            size="lg"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            type={canSubmit ? "submit" : "button"}
            size="lg"
            onClick={handlePrimaryClick}
          >
            {isSubmitting
              ? "Updating..."
              : canSubmit
                ? "Update note"
                : isCloudOnly
                  ? "Only in Cloud"
                  : "Unavailable"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export {
  FindingTriageStatusControl,
  isMutelistShortcutStatus,
  TriageStatusSelect,
};
