"use client";

import { MessageSquareText } from "lucide-react";
import { useState } from "react";

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
  type FindingTriageSummary,
} from "@/types/findings-triage";

import {
  FindingNoteModal,
  type FindingTriageContext,
  FindingTriageStatusControl,
  type FindingTriageUpdateHandler,
} from "./finding-note-modal";

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
  noteBody = "",
): FindingTriageDetail => ({
  ...triage,
  noteBody,
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
}: {
  triage?: FindingTriageSummary;
  findingContext?: FindingTriageContext;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
}) {
  const [isNoteModalOpen, setIsNoteModalOpen] = useState(false);

  if (!triage) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  const hasUpdateHandler = Boolean(onTriageUpdateAction);
  const canOpenNoteModal = triage.hasVisibleNote
    ? false
    : triage.canEdit
      ? hasUpdateHandler
      : triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY;
  const disabledCopy = getDisabledCopy({ triage, hasUpdateHandler });

  const noteModal = isNoteModalOpen ? (
    <FindingNoteModal
      open={isNoteModalOpen}
      onOpenChange={setIsNoteModalOpen}
      triage={getTriageDetailFromSummary(triage)}
      findingContext={findingContext}
      onTriageUpdateAction={onTriageUpdateAction}
    />
  ) : null;

  if (triage.hasVisibleNote) {
    return (
      <>
        <button
          type="button"
          aria-label="Note exists"
          title="Existing notes cannot be edited from the table."
          disabled
          className="text-text-success-primary inline-flex cursor-not-allowed items-center opacity-60"
          onClick={(event) => {
            event.stopPropagation();
          }}
        >
          <MessageSquareText className="size-4" aria-hidden="true" />
        </button>
        {noteModal}
      </>
    );
  }

  return (
    <>
      <button
        type="button"
        disabled={!canOpenNoteModal}
        title={disabledCopy}
        className="text-button-tertiary hover:text-button-tertiary-hover inline-flex items-center gap-1.5 text-sm font-medium transition-colors hover:underline disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:no-underline"
        onClick={(event) => {
          event.stopPropagation();
          if (canOpenNoteModal) {
            setIsNoteModalOpen(true);
          }
        }}
      >
        <MessageSquareText className="size-4" aria-hidden="true" />
        <span>Add note</span>
      </button>
      {noteModal}
    </>
  );
}
