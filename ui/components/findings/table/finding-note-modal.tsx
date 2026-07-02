"use client";

import { type FormEvent, useRef, useState } from "react";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Alert, AlertDescription, Button, Textarea } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { CloudFeatureBadgeLink } from "@/components/shared/cloud-feature-badge";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { DOCS_URLS } from "@/lib/external-urls";
import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_RESOLVED_LOCKED_COPY,
  FINDING_TRIAGE_STATUS,
  type FindingTriageDetail,
  type FindingTriageStatus,
  getFindingTriageMuteInfoCopy,
  isMutelistShortcutStatus,
  isTriageStatusLocked,
} from "@/types/findings-triage";
import type { ProviderType } from "@/types/providers";

import {
  FindingTriageStatusControl,
  type FindingTriageUpdateHandler,
} from "./finding-triage-status-control";
import { buildFindingTriageUpdateInput } from "./finding-triage-submit";

export interface FindingTriageContext {
  title: string;
  resource?: string;
  provider?: string;
  providerType?: ProviderType;
}

interface FindingNoteModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  triage: FindingTriageDetail;
  findingContext: FindingTriageContext;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
}

const REMEDIATING_INFO_COPY =
  "Once this finding is remediated, if in the following scan its status changes to Pass, it will be automatically changed to Resolved";

export function FindingNoteModal({
  open,
  onOpenChange,
  triage,
  findingContext,
  onTriageUpdateAction,
}: FindingNoteModalProps) {
  // Local state needed: modal edits are buffered until the user chooses Update.
  const [selectedStatus, setSelectedStatus] = useState<FindingTriageStatus>(
    triage.status,
  );
  const [note, setNote] = useState(triage.noteBody);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const noteTextareaRef = useRef<HTMLTextAreaElement>(null);
  const canSubmit =
    triage.canEdit && Boolean(onTriageUpdateAction) && !isSubmitting;
  const isCloudOnly =
    triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY;
  const shouldShowMutelistInfo =
    canSubmit &&
    !triage.isMuted &&
    selectedStatus !== triage.status &&
    isMutelistShortcutStatus(selectedStatus);
  const shouldShowRemediatingInfo =
    selectedStatus === FINDING_TRIAGE_STATUS.REMEDIATING;
  const isStatusLocked = isTriageStatusLocked(triage.status);
  // Opened from a dropdown item: move focus into the dialog on mount so Radix's
  // aria-hidden is not applied to the still-focused dropdown that opened it.
  const handleOpenAutoFocus = (event: Event) => {
    const textarea = noteTextareaRef.current;
    if (textarea && !textarea.disabled) {
      event.preventDefault();
      textarea.focus();
    }
    // Otherwise let Radix auto-focus the first control inside the dialog.
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!canSubmit) {
      return;
    }

    setSubmitError(null);
    setIsSubmitting(true);

    try {
      const updateInput = buildFindingTriageUpdateInput({
        triage,
        selectedStatus,
        noteBody: note,
      });

      if (!updateInput) {
        onOpenChange(false);
        return;
      }

      await onTriageUpdateAction?.(updateInput);
      onOpenChange(false);
    } catch {
      setSubmitError("Could not update the note. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      onOpenAutoFocus={handleOpenAutoFocus}
      title="Add Triage Note"
      size="lg"
    >
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

        <div className="flex items-center justify-end gap-3">
          <span className="text-text-neutral-primary text-sm font-semibold">
            Status:
          </span>
          <div className="w-1/2 min-w-44">
            <FindingTriageStatusControl
              origin={FINDING_TRIAGE_ORIGIN.MODAL}
              triage={triage}
              value={selectedStatus}
              onValueChange={setSelectedStatus}
            />
          </div>
        </div>

        {isStatusLocked && (
          <Alert variant="info">
            <AlertDescription>
              {FINDING_TRIAGE_RESOLVED_LOCKED_COPY}
            </AlertDescription>
          </Alert>
        )}

        {shouldShowMutelistInfo && (
          <Alert variant="warning">
            <AlertDescription>
              {getFindingTriageMuteInfoCopy(selectedStatus)}
            </AlertDescription>
          </Alert>
        )}

        {shouldShowRemediatingInfo && (
          <Alert variant="info">
            <AlertDescription>
              {REMEDIATING_INFO_COPY}.{" "}
              <CustomLink href={DOCS_URLS.FINDINGS_TRIAGE} size="sm">
                Learn more
              </CustomLink>
            </AlertDescription>
          </Alert>
        )}

        {submitError && (
          <Alert variant="error">
            <AlertDescription>{submitError}</AlertDescription>
          </Alert>
        )}

        <div className="space-y-2">
          <Textarea
            ref={noteTextareaRef}
            id="finding-triage-note"
            aria-label="Note text"
            value={note}
            maxLength={triage.maxNoteLength}
            disabled={!canSubmit}
            textareaSize="lg"
            onChange={(event) => setNote(event.target.value)}
          />
          <div className="flex items-center justify-end">
            <p className="text-text-neutral-tertiary shrink-0 text-xs">
              {note.length}/{triage.maxNoteLength}
            </p>
          </div>
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
          <span className="relative inline-flex">
            {isCloudOnly && (
              <span className="absolute top-0 right-0 z-10 translate-x-1/3 -translate-y-1/2">
                <CloudFeatureBadgeLink href={triage.billingHref} />
              </span>
            )}
            <Button
              type={canSubmit ? "submit" : "button"}
              size="lg"
              disabled={!canSubmit}
            >
              {isSubmitting
                ? "Saving..."
                : canSubmit || isCloudOnly
                  ? "Save changes"
                  : "Unavailable"}
            </Button>
          </span>
        </div>
      </form>
    </Modal>
  );
}
