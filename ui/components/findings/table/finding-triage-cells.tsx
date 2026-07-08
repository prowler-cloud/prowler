"use client";

import { MessageSquareText } from "lucide-react";
import { useState } from "react";

import { ActionDropdownItem } from "@/components/shadcn/dropdown";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_RESOLVED_LOCKED_COPY,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageDetail,
  type FindingTriageLoadedNote,
  type FindingTriageStatus,
  type FindingTriageSummary,
  isTriageStatusLocked,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

import {
  FindingNoteModal,
  type FindingTriageContext,
} from "./finding-note-modal";
import {
  FindingTriageStatusControl,
  type FindingTriageUpdateHandler,
  TRIAGE_STATUS_TEXT_CLASS,
} from "./finding-triage-status-control";

export const CLOUD_ONLY_TOOLTIP_COPY = "Available in Prowler Cloud";
export const EDITING_UNAVAILABLE_COPY = "Editing is currently unavailable.";

const getDisabledCopy = ({
  triage,
  hasUpdateHandler,
  lockResolved = false,
}: {
  triage: FindingTriageSummary;
  hasUpdateHandler: boolean;
  lockResolved?: boolean;
}): string | undefined => {
  if (triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY) {
    return CLOUD_ONLY_TOOLTIP_COPY;
  }

  // Status-picker only: notes stay available on resolved findings.
  if (lockResolved && isTriageStatusLocked(triage.status)) {
    return FINDING_TRIAGE_RESOLVED_LOCKED_COPY;
  }

  if (triage.canEdit && !hasUpdateHandler) {
    return EDITING_UNAVAILABLE_COPY;
  }

  return undefined;
};

const getTriageDetailFromSummary = (
  triage: FindingTriageSummary,
  loadedNote?: FindingTriageLoadedNote,
): FindingTriageDetail => ({
  ...triage,
  noteId: loadedNote?.noteId ?? null,
  noteBody: loadedNote?.noteBody ?? "",
  maxNoteLength: FINDING_TRIAGE_NOTE_MAX_LENGTH,
});

export function FindingTriageStatusCell({
  triage,
  onTriageUpdateAction,
}: {
  triage?: FindingTriageSummary;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
}) {
  const [optimisticStatus, setOptimisticStatus] = useState<{
    token: string;
    findingId: string;
    triageId: string | null;
    previousStatus: FindingTriageStatus;
    status: FindingTriageStatus;
  } | null>(null);

  // Retire the optimistic status once the server converges or the row changes, so a stale value can't resurface.
  if (
    optimisticStatus &&
    (!triage ||
      optimisticStatus.findingId !== triage.findingId ||
      optimisticStatus.triageId !== triage.triageId ||
      triage.status === optimisticStatus.status)
  ) {
    setOptimisticStatus(null);
  }

  const optimisticMatchesCurrentTriage =
    Boolean(triage) &&
    optimisticStatus?.findingId === triage?.findingId &&
    optimisticStatus?.triageId === triage?.triageId &&
    optimisticStatus?.previousStatus === triage?.status &&
    optimisticStatus?.status !== triage?.status;

  if (!triage) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  const displayedTriage =
    optimisticMatchesCurrentTriage && optimisticStatus
      ? {
          ...triage,
          status: optimisticStatus.status,
          label: FINDING_TRIAGE_STATUS_LABELS[optimisticStatus.status],
        }
      : triage;

  const handleTriageUpdate = async (input: UpdateFindingTriageInput) => {
    const optimisticToken = input.status ? crypto.randomUUID() : null;

    if (input.status && optimisticToken) {
      setOptimisticStatus({
        token: optimisticToken,
        findingId: input.findingId,
        triageId: input.triageId,
        previousStatus: input.previousStatus ?? triage.status,
        status: input.status,
      });
    }

    try {
      await onTriageUpdateAction?.(input);
    } catch (error) {
      setOptimisticStatus((current) =>
        current?.token === optimisticToken ? null : current,
      );
      throw error;
    }
  };

  const control = (
    <div
      onClick={(event) => event.stopPropagation()}
      onPointerDown={(event) => event.stopPropagation()}
    >
      <FindingTriageStatusControl
        key={displayedTriage.findingId}
        origin={FINDING_TRIAGE_ORIGIN.TABLE}
        triage={displayedTriage}
        onTriageUpdateAction={
          onTriageUpdateAction ? handleTriageUpdate : undefined
        }
      />
    </div>
  );

  const disabledCopy = getDisabledCopy({
    triage,
    hasUpdateHandler: Boolean(onTriageUpdateAction),
    lockResolved: true,
  });
  if (!disabledCopy) {
    return control;
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* Block-level wrapper keeps the picker aligned with the sibling columns. */}
        <span className="flex">{control}</span>
      </TooltipTrigger>
      <TooltipContent>{disabledCopy}</TooltipContent>
    </Tooltip>
  );
}

// Read-only triage status indicator, e.g. for the side drawer header where the
// editable picker would be out of place among the status/severity badges.
export function FindingTriageStatusBadge({
  triage,
}: {
  triage: FindingTriageSummary;
}) {
  return (
    <div className="flex items-center gap-1">
      <span className="text-text-neutral-tertiary text-xs">Triage:</span>
      <span
        className={cn(
          "text-xs font-medium",
          TRIAGE_STATUS_TEXT_CLASS[triage.status],
        )}
      >
        {triage.label}
      </span>
    </div>
  );
}

export function FindingNoteActionItem({
  triage,
  findingContext = { title: "Finding" },
  onTriageUpdateAction,
  onTriageNoteLoadAction,
}: {
  triage?: FindingTriageSummary;
  findingContext?: FindingTriageContext;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onTriageNoteLoadAction?: (
    triage: FindingTriageSummary,
  ) => Promise<FindingTriageLoadedNote>;
}) {
  if (!triage) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  const triageIdentity = `${triage.findingId}:${triage.triageId ?? "virtual"}`;

  return (
    <FindingNoteActionItemContent
      key={triageIdentity}
      triage={triage}
      findingContext={findingContext}
      onTriageUpdateAction={onTriageUpdateAction}
      onTriageNoteLoadAction={onTriageNoteLoadAction}
    />
  );
}

function FindingNoteActionItemContent({
  triage,
  findingContext,
  onTriageUpdateAction,
  onTriageNoteLoadAction,
}: {
  triage: FindingTriageSummary;
  findingContext: FindingTriageContext;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onTriageNoteLoadAction?: (
    triage: FindingTriageSummary,
  ) => Promise<FindingTriageLoadedNote>;
}) {
  const [isNoteModalOpen, setIsNoteModalOpen] = useState(false);
  const [loadedNote, setLoadedNote] = useState<FindingTriageLoadedNote>();
  const [isLoadingNote, setIsLoadingNote] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const hasUpdateHandler = Boolean(onTriageUpdateAction);
  const isCloudOnly =
    triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY;
  const canOpenNewNoteModal =
    !triage.hasVisibleNote &&
    ((triage.canEdit && hasUpdateHandler) || isCloudOnly);
  const canOpenExistingNoteModal =
    triage.hasVisibleNote &&
    triage.canEdit &&
    hasUpdateHandler &&
    Boolean(onTriageNoteLoadAction) &&
    !isLoadingNote;
  const disabledCopy = getDisabledCopy({ triage, hasUpdateHandler });
  const canOpenNoteModal = triage.hasVisibleNote
    ? canOpenExistingNoteModal
    : canOpenNewNoteModal;
  const label = isLoadingNote
    ? "Loading note..."
    : triage.hasVisibleNote
      ? "Open note"
      : "Add Triage Note";

  const handleNoteSelect = async () => {
    if (!canOpenNoteModal) {
      return;
    }

    if (!triage.hasVisibleNote) {
      setIsNoteModalOpen(true);
      return;
    }

    if (!onTriageNoteLoadAction) {
      return;
    }

    setLoadError(null);
    setIsLoadingNote(true);

    try {
      const note = await onTriageNoteLoadAction(triage);
      setLoadedNote(note);
      setIsNoteModalOpen(true);
    } catch {
      setLoadError("Could not load the existing note.");
    } finally {
      setIsLoadingNote(false);
    }
  };

  const noteModal = isNoteModalOpen ? (
    <FindingNoteModal
      open={isNoteModalOpen}
      onOpenChange={setIsNoteModalOpen}
      triage={getTriageDetailFromSummary(triage, loadedNote)}
      findingContext={findingContext}
      onTriageUpdateAction={onTriageUpdateAction}
    />
  ) : null;

  return (
    <>
      <ActionDropdownItem
        icon={<MessageSquareText className="size-5" />}
        label={label}
        disabled={!canOpenNoteModal}
        title={
          triage.hasVisibleNote && !canOpenExistingNoteModal
            ? "Existing note cannot be loaded from the table."
            : disabledCopy
        }
        onSelect={(event) => {
          event.preventDefault();
          void handleNoteSelect();
        }}
      />
      {loadError && (
        <span className="sr-only" role="alert">
          {loadError}
        </span>
      )}
      {noteModal}
    </>
  );
}
