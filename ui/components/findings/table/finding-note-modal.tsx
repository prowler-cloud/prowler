"use client";

import { type FormEvent, useState } from "react";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Alert, AlertDescription, Button, Textarea } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { CloudFeatureBadgeLink } from "@/components/shared/cloud-feature-badge";
import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_STATUS,
  type FindingTriageDetail,
  type FindingTriageStatus,
} from "@/types/findings-triage";
import type { ProviderType } from "@/types/providers";

import {
  FindingTriageStatusControl,
  FindingTriageStatusDot,
  type FindingTriageUpdateHandler,
  isMutelistShortcutStatus,
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

const MUTELIST_INFO_COPY =
  "This finding will be muted through the existing Mutelist flow.";
const REMEDIATING_INFO_COPY =
  "Once this finding is fixed and passes in the next scan, it will be automatically changed to Resolved.";

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
  const canSubmit =
    triage.canEdit && Boolean(onTriageUpdateAction) && !isSubmitting;
  const isCloudOnly =
    triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY;
  const shouldShowMutelistInfo =
    canSubmit && isMutelistShortcutStatus(selectedStatus);
  const shouldShowRemediatingInfo =
    selectedStatus === FINDING_TRIAGE_STATUS.REMEDIATING;
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
        origin: FINDING_TRIAGE_ORIGIN.MODAL,
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
          <FindingTriageStatusDot status={selectedStatus} />
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

        {shouldShowRemediatingInfo && (
          <Alert variant="info">
            <AlertDescription>{REMEDIATING_INFO_COPY}</AlertDescription>
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
