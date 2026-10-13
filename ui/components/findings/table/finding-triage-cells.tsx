"use client";

import { MessageSquareText } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import { ActionDropdownItem } from "@/components/shadcn/dropdown";
import { useToast } from "@/components/shadcn/toast/use-toast";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { applyOptimisticTriageSummaryUpdate } from "@/lib/finding-triage";
import { cn } from "@/lib/utils";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import { FINDING_STATUS } from "@/types/components";
import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_RESOLVED_LOCKED_COPY,
  FINDING_TRIAGE_STATUS,
  type FindingTriageContext,
  type FindingTriageDetail,
  type FindingTriageDetailLoadHandler,
  type FindingTriageLoadedNote,
  type FindingTriageNoteLoadHandler,
  type FindingTriageSummary,
  type FindingTriageUpdateHandler,
  isManualStatus,
  isTriageStatusLocked,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

import {
  FINDING_NOTE_MODAL_MODE,
  FindingNoteModal,
  type FindingNoteModalMode,
} from "./finding-note-modal";
import {
  FindingTriageStatusControl,
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
  rawFindingStatus: triage.rawFindingStatus ?? null,
  manualPassCreatedByName: null,
  manualPassCreatedAt: null,
  manualPassExpiresAt: null,
  manualPassActive: null,
  manualPassEvidence: null,
  manualPassDeactivatedAt: null,
});

const getManualPassModalInitialStatus = (
  mode: FindingNoteModalMode,
  detail: FindingTriageDetail,
) => {
  if (
    mode === FINDING_NOTE_MODAL_MODE.MANUAL_PASS_DETAILS &&
    detail.status === FINDING_TRIAGE_STATUS.RESOLVED
  ) {
    return FINDING_TRIAGE_STATUS.RESOLVED;
  }

  if (
    mode === FINDING_NOTE_MODAL_MODE.EDIT &&
    detail.rawFindingStatus === FINDING_STATUS.MANUAL
  ) {
    return FINDING_TRIAGE_STATUS.RESOLVED;
  }

  return isManualStatus(detail.status)
    ? detail.status
    : FINDING_TRIAGE_STATUS.OPEN;
};

export function FindingTriageStatusCell({
  triage,
  findingContext = { title: "Finding" },
  onTriageUpdateAction,
  onTriageDetailLoadAction,
}: {
  triage?: FindingTriageSummary;
  findingContext?: FindingTriageContext;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onTriageDetailLoadAction?: FindingTriageDetailLoadHandler;
}) {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );
  const [optimisticStatus, setOptimisticStatus] = useState<{
    token: string;
    input: UpdateFindingTriageInput;
  } | null>(null);
  const [manualPassDetail, setManualPassDetail] =
    useState<FindingTriageDetail>();
  const [manualPassModalMode, setManualPassModalMode] =
    useState<FindingNoteModalMode>(FINDING_NOTE_MODAL_MODE.EDIT);
  const [isManualPassModalOpen, setIsManualPassModalOpen] = useState(false);
  const [isManualPassLoading, setIsManualPassLoading] = useState(false);
  const [manualPassLoadError, setManualPassLoadError] = useState<string | null>(
    null,
  );

  // Retire the optimistic status once the server converges or the row changes, so a stale value can't resurface.
  if (
    optimisticStatus &&
    (!triage ||
      optimisticStatus.input.findingId !== triage.findingId ||
      optimisticStatus.input.triageId !== triage.triageId ||
      triage.status === optimisticStatus.input.status)
  ) {
    setOptimisticStatus(null);
  }

  const optimisticMatchesCurrentTriage =
    Boolean(triage) &&
    optimisticStatus?.input.findingId === triage?.findingId &&
    optimisticStatus?.input.triageId === triage?.triageId &&
    (optimisticStatus?.input.previousStatus ?? triage?.status) ===
      triage?.status &&
    optimisticStatus?.input.status !== triage?.status;

  if (!triage) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  const displayedTriage =
    optimisticMatchesCurrentTriage && optimisticStatus
      ? applyOptimisticTriageSummaryUpdate(triage, optimisticStatus.input)
      : triage;
  const interactiveTriage = isManualPassLoading
    ? { ...displayedTriage, canEdit: false }
    : displayedTriage;

  const handleTriageUpdate = async (input: UpdateFindingTriageInput) => {
    const optimisticToken = input.status ? crypto.randomUUID() : null;

    if (input.status && optimisticToken) {
      setOptimisticStatus({
        token: optimisticToken,
        input,
      });
    }

    try {
      return await onTriageUpdateAction?.(input);
    } catch (error) {
      setOptimisticStatus((current) =>
        current?.token === optimisticToken ? null : current,
      );
      throw error;
    }
  };

  const handleManualPassRequest = async (
    mode: FindingNoteModalMode = FINDING_NOTE_MODAL_MODE.EDIT,
  ) => {
    if (!onTriageDetailLoadAction) {
      return;
    }

    setManualPassLoadError(null);
    setIsManualPassLoading(true);

    try {
      const detail = await onTriageDetailLoadAction(triage);

      if (!detail) {
        throw new Error("Missing triage detail");
      }

      setManualPassDetail(detail);
      setManualPassModalMode(mode);
      setIsManualPassModalOpen(true);
    } catch {
      setManualPassLoadError("Could not load current triage details.");
    } finally {
      setIsManualPassLoading(false);
    }
  };

  const control = (
    <div
      className="flex w-32 flex-col items-start gap-1"
      onClick={(event) => event.stopPropagation()}
      onPointerDown={(event) => event.stopPropagation()}
    >
      <FindingTriageStatusControl
        key={displayedTriage.findingId}
        origin={FINDING_TRIAGE_ORIGIN.TABLE}
        triage={interactiveTriage}
        onTriageUpdateAction={
          onTriageUpdateAction ? handleTriageUpdate : undefined
        }
        onManualPassRequest={
          onTriageDetailLoadAction
            ? () => void handleManualPassRequest()
            : undefined
        }
      />
      {displayedTriage.manualPassProvenance && (
        <>
          {onTriageDetailLoadAction ? (
            <Button
              type="button"
              variant="link"
              size="link-xs"
              aria-label="View Manual Pass details"
              disabled={isManualPassLoading}
              onClick={() =>
                void handleManualPassRequest(
                  FINDING_NOTE_MODAL_MODE.MANUAL_PASS_DETAILS,
                )
              }
            >
              {displayedTriage.manualPassProvenance}
            </Button>
          ) : (
            <span className="text-text-neutral-tertiary text-xs">
              {displayedTriage.manualPassProvenance}
            </span>
          )}
        </>
      )}
    </div>
  );

  const disabledCopy = getDisabledCopy({
    triage,
    hasUpdateHandler: Boolean(onTriageUpdateAction),
    lockResolved: true,
  });
  const manualPassModal =
    manualPassDetail && isManualPassModalOpen ? (
      <FindingNoteModal
        open={isManualPassModalOpen}
        onOpenChange={setIsManualPassModalOpen}
        triage={manualPassDetail}
        findingContext={findingContext}
        mode={manualPassModalMode}
        initialStatus={getManualPassModalInitialStatus(
          manualPassModalMode,
          manualPassDetail,
        )}
        onTriageUpdateAction={
          manualPassModalMode === FINDING_NOTE_MODAL_MODE.EDIT
            ? handleTriageUpdate
            : undefined
        }
      />
    ) : null;
  const statusContent = (
    <>
      {control}
      {manualPassLoadError && (
        <span className="text-text-error-primary text-xs" role="alert">
          {manualPassLoadError}
        </span>
      )}
      {manualPassModal}
    </>
  );

  if (!disabledCopy) {
    return statusContent;
  }

  if (triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="relative flex">
            {statusContent}
            <Button
              type="button"
              variant="bare"
              size="link-xs"
              aria-label="Change triage status - available in Prowler Cloud"
              className="absolute inset-0 h-auto w-auto rounded-lg"
              onPointerDown={(event) => event.stopPropagation()}
              onClick={(event) => {
                event.stopPropagation();
                openCloudUpgrade(CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE);
              }}
            />
          </span>
        </TooltipTrigger>
        <TooltipContent>{disabledCopy}</TooltipContent>
      </Tooltip>
    );
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {/* Block-level wrapper keeps the picker aligned with the sibling columns. */}
        <span className="flex">{statusContent}</span>
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
  onTriageDetailLoadAction,
}: {
  triage?: FindingTriageSummary;
  findingContext?: FindingTriageContext;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onTriageNoteLoadAction?: FindingTriageNoteLoadHandler;
  onTriageDetailLoadAction?: FindingTriageDetailLoadHandler;
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
      onTriageDetailLoadAction={onTriageDetailLoadAction}
    />
  );
}

function FindingNoteActionItemContent({
  triage,
  findingContext,
  onTriageUpdateAction,
  onTriageNoteLoadAction,
  onTriageDetailLoadAction,
}: {
  triage: FindingTriageSummary;
  findingContext: FindingTriageContext;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onTriageNoteLoadAction?: FindingTriageNoteLoadHandler;
  onTriageDetailLoadAction?: FindingTriageDetailLoadHandler;
}) {
  const { toast } = useToast();
  const [isNoteModalOpen, setIsNoteModalOpen] = useState(false);
  const [loadedNote, setLoadedNote] = useState<FindingTriageLoadedNote>();
  const [loadedDetail, setLoadedDetail] = useState<FindingTriageDetail>();
  const [isLoadingNote, setIsLoadingNote] = useState(false);

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

    if (isCloudOnly || (!onTriageDetailLoadAction && !triage.hasVisibleNote)) {
      setIsNoteModalOpen(true);
      return;
    }

    setIsLoadingNote(true);

    try {
      const [detail, note] = await Promise.all([
        onTriageDetailLoadAction
          ? onTriageDetailLoadAction(triage)
          : Promise.resolve(getTriageDetailFromSummary(triage)),
        triage.hasVisibleNote && onTriageNoteLoadAction
          ? onTriageNoteLoadAction(triage)
          : Promise.resolve(undefined),
      ]);
      setLoadedDetail(detail);
      if (note) {
        setLoadedNote(note);
      }
      setIsNoteModalOpen(true);
    } catch {
      toast({
        variant: "destructive",
        title: triage.hasVisibleNote
          ? "Could not load the existing note."
          : "Could not load current triage details.",
        description: "Please try again.",
      });
    } finally {
      setIsLoadingNote(false);
    }
  };

  const noteModal = isNoteModalOpen ? (
    <FindingNoteModal
      open={isNoteModalOpen}
      onOpenChange={setIsNoteModalOpen}
      triage={
        loadedDetail
          ? {
              ...loadedDetail,
              noteId: loadedNote?.noteId ?? loadedDetail.noteId,
              noteBody: loadedNote?.noteBody ?? loadedDetail.noteBody,
            }
          : getTriageDetailFromSummary(triage, loadedNote)
      }
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
      {noteModal}
    </>
  );
}
