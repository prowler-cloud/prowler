"use client";

import { MessageSquareText } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  FINDING_TRIAGE_NOTE_PRIVACY_COPY,
  FINDING_TRIAGE_ORIGIN,
  type FindingTriageDetail,
  type FindingTriageLoadedNote,
  type FindingTriageSummary,
} from "@/types/findings-triage";

import {
  FindingNoteModal,
  type FindingTriageContext,
} from "./finding-note-modal";
import {
  FindingTriageStatusControl,
  type FindingTriageUpdateHandler,
} from "./finding-triage-status-control";

const CLOUD_ONLY_TOOLTIP_COPY = "This feature is only in Cloud.";
const EDITING_UNAVAILABLE_COPY = "Editing is currently unavailable.";

const getDisabledCopy = ({
  triage,
  hasUpdateHandler,
}: {
  triage: FindingTriageSummary;
  hasUpdateHandler: boolean;
}): string | undefined => {
  if (triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY) {
    return CLOUD_ONLY_TOOLTIP_COPY;
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
  privacyCopy: FINDING_TRIAGE_NOTE_PRIVACY_COPY,
});

export function FindingTriageStatusCell({
  triage,
  onTriageUpdateAction,
}: {
  triage?: FindingTriageSummary;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
}) {
  if (!triage) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  const control = (
    <div
      onClick={(event) => event.stopPropagation()}
      onPointerDown={(event) => event.stopPropagation()}
    >
      <FindingTriageStatusControl
        key={`${triage.findingId}:${triage.status}`}
        origin={FINDING_TRIAGE_ORIGIN.TABLE}
        triage={triage}
        onTriageUpdateAction={onTriageUpdateAction}
      />
    </div>
  );

  const disabledCopy = getDisabledCopy({
    triage,
    hasUpdateHandler: Boolean(onTriageUpdateAction),
  });
  if (!disabledCopy) {
    return control;
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex">{control}</span>
      </TooltipTrigger>
      <TooltipContent>{disabledCopy}</TooltipContent>
    </Tooltip>
  );
}

export function FindingNotesCell({
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
  const [isNoteModalOpen, setIsNoteModalOpen] = useState(false);
  const [loadedNote, setLoadedNote] = useState<FindingTriageLoadedNote>();
  const [isLoadingNote, setIsLoadingNote] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  if (!triage) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

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

  const noteModal = isNoteModalOpen ? (
    <FindingNoteModal
      open={isNoteModalOpen}
      onOpenChange={setIsNoteModalOpen}
      triage={getTriageDetailFromSummary(triage, loadedNote)}
      findingContext={findingContext}
      onTriageUpdateAction={onTriageUpdateAction}
    />
  ) : null;

  if (triage.hasVisibleNote) {
    return (
      <>
        <Button
          type="button"
          variant="bare-success"
          size="icon-xs"
          aria-label="Note exists"
          title={
            canOpenExistingNoteModal
              ? "Open note"
              : "Existing note cannot be loaded from the table."
          }
          disabled={!canOpenExistingNoteModal}
          onClick={async (event) => {
            event.stopPropagation();
            if (!canOpenExistingNoteModal || !onTriageNoteLoadAction) {
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
          }}
        >
          <MessageSquareText className="size-4" aria-hidden="true" />
        </Button>
        {loadError && (
          <span className="sr-only" role="alert">
            {loadError}
          </span>
        )}
        {noteModal}
      </>
    );
  }

  return (
    <>
      <Button
        type="button"
        variant="link"
        size="link-inline"
        disabled={!canOpenNewNoteModal}
        title={disabledCopy}
        onClick={(event) => {
          event.stopPropagation();
          if (canOpenNewNoteModal) {
            setIsNoteModalOpen(true);
          }
        }}
      >
        <MessageSquareText className="size-4" aria-hidden="true" />
        <span>Add note</span>
      </Button>
      {noteModal}
    </>
  );
}
