"use client";

import { ExternalLink, Info } from "lucide-react";
import { type FormEvent, useRef, useState } from "react";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import {
  Alert,
  AlertDescription,
  Badge,
  Button,
  Textarea,
  useToast,
} from "@/components/shadcn";
import { DateWithTime } from "@/components/shadcn/entities";
import { Field, FieldLabel } from "@/components/shadcn/field/field";
import { Modal } from "@/components/shadcn/modal";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { formatLocalDate } from "@/lib/date-utils";
import { DOCS_URLS } from "@/lib/external-urls";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import { FINDING_STATUS } from "@/types/components";
import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_RESOLVED_LOCKED_COPY,
  FINDING_TRIAGE_STATUS,
  MANUAL_PASS_PROVENANCE,
  type FindingTriageContext,
  type FindingTriageDetail,
  type FindingTriageModalStatus,
  type FindingTriageUpdateHandler,
  getFindingTriageMuteInfoCopy,
  isManualStatus,
  isMutelistShortcutStatus,
  isTriageStatusLocked,
} from "@/types/findings-triage";

import {
  FindingTriageStatusControl,
  MANUAL_PASS_NOTE_REQUIRED_COPY,
} from "./finding-triage-status-control";
import { buildFindingTriageUpdateInput } from "./finding-triage-submit";

interface FindingNoteModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  triage: FindingTriageDetail;
  findingContext: FindingTriageContext;
  mode?: FindingNoteModalMode;
  initialStatus?: FindingTriageModalStatus;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
}

export const FINDING_NOTE_MODAL_MODE = {
  EDIT: "edit",
  MANUAL_PASS_DETAILS: "manual-pass-details",
} as const;

export type FindingNoteModalMode =
  (typeof FINDING_NOTE_MODAL_MODE)[keyof typeof FINDING_NOTE_MODAL_MODE];

const REMEDIATING_INFO_COPY =
  "Once this finding is remediated, if in the following scan its status changes to Pass, it will be automatically changed to Resolved";

export function FindingNoteModal({
  open,
  onOpenChange,
  triage,
  findingContext,
  mode = FINDING_NOTE_MODAL_MODE.EDIT,
  initialStatus,
  onTriageUpdateAction,
}: FindingNoteModalProps) {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );
  const { toast } = useToast();
  const initialSelectedStatus =
    initialStatus ??
    (triage.status === FINDING_TRIAGE_STATUS.RESOLVED ||
    isManualStatus(triage.status)
      ? triage.status
      : FINDING_TRIAGE_STATUS.OPEN);
  // Local state needed: modal edits are buffered until the user chooses Update.
  const [selectedStatus, setSelectedStatus] =
    useState<FindingTriageModalStatus>(initialSelectedStatus);
  const [note, setNote] = useState(triage.noteBody);
  const [manualPassEvidence, setManualPassEvidence] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const noteTextareaRef = useRef<HTMLTextAreaElement>(null);
  const isManualPassDetails =
    mode === FINDING_NOTE_MODAL_MODE.MANUAL_PASS_DETAILS;
  const canEdit =
    !isManualPassDetails &&
    triage.canEdit &&
    Boolean(onTriageUpdateAction) &&
    !isSubmitting;
  const isManualPassSelected =
    selectedStatus === FINDING_TRIAGE_STATUS.RESOLVED &&
    triage.rawFindingStatus === FINDING_STATUS.MANUAL &&
    triage.status !== FINDING_TRIAGE_STATUS.RESOLVED;
  const canSubmit =
    canEdit && (!isManualPassSelected || manualPassEvidence.trim().length > 0);
  const isCloudOnly =
    triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY;
  const shouldShowMutelistInfo =
    canEdit &&
    !triage.isMuted &&
    selectedStatus !== triage.status &&
    isMutelistShortcutStatus(selectedStatus);
  const shouldShowRemediatingInfo =
    selectedStatus === FINDING_TRIAGE_STATUS.REMEDIATING;
  const isStatusLocked = isTriageStatusLocked(triage.status);
  const shouldShowManualPassProvenance =
    triage.manualPassCreatedAt !== null && triage.manualPassExpiresAt !== null;
  const isPreviousManualPass = triage.manualPassActive === false;
  const manualPassState =
    triage.manualPassActive === true
      ? "Active"
      : isPreviousManualPass
        ? triage.manualPassDeactivatedAt
          ? "Inactive"
          : "Expired"
        : null;
  const hasManualPassEvidence = Boolean(triage.manualPassEvidence?.trim());
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

  const handleOpenChange = (nextOpen: boolean) => {
    if (!nextOpen) {
      setSelectedStatus(initialSelectedStatus);
      setNote(triage.noteBody);
      setManualPassEvidence("");
      setSubmitError(null);
    }
    onOpenChange(nextOpen);
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
        manualPassEvidence,
      });

      if (!updateInput) {
        handleOpenChange(false);
        return;
      }

      const updateResult = await onTriageUpdateAction?.(updateInput);

      if (isManualPassSelected && updateResult?.manualPassExpiresAt) {
        const formattedExpiry = formatLocalDate(
          updateResult.manualPassExpiresAt,
        );

        toast({
          title: "Finding manually verified as Pass",
          description: formattedExpiry
            ? `Triage: Resolved · Valid until ${formattedExpiry}`
            : "Triage: Resolved",
        });
      }

      handleOpenChange(false);
    } catch (error) {
      setSubmitError(
        error instanceof Error
          ? error.message
          : "Could not update the note. Please try again.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      open={open}
      onOpenChange={handleOpenChange}
      onOpenAutoFocus={handleOpenAutoFocus}
      title={isManualPassDetails ? "Manual Pass Details" : "Add Triage Note"}
      description={
        isManualPassDetails
          ? "Authoritative Manual Pass evidence and provenance."
          : undefined
      }
      size="lg"
    >
      {/* min-w-0: the form is a grid item of DialogContent; without it, long
          unbreakable content (e.g. resource UIDs) widens the grid track past
          the modal instead of truncating. */}
      <form className="flex min-w-0 flex-col gap-5" onSubmit={handleSubmit}>
        {!isManualPassDetails && (
          <div className="text-text-neutral-secondary flex flex-wrap items-center gap-2 text-sm">
            <Info className="size-4 shrink-0" />
            <span>Learn how triage states work in the</span>
            <Button
              variant="link"
              size="link-sm"
              className="h-auto p-0"
              asChild
            >
              <a
                href={DOCS_URLS.FINDINGS_TRIAGE}
                target="_blank"
                rel="noopener noreferrer"
              >
                <ExternalLink className="size-3.5 shrink-0" />
                <span>Triage documentation</span>
              </a>
            </Button>
          </div>
        )}

        <div className="border-border-input-primary flex items-center gap-4 rounded-lg border p-3">
          <div className="bg-bg-neutral-tertiary flex size-9 shrink-0 items-center justify-center overflow-hidden rounded-lg">
            {findingContext.providerType ? (
              <ProviderTypeIcon type={findingContext.providerType} size={36} />
            ) : (
              <span className="text-text-neutral-secondary text-xs font-semibold">
                {findingContext.provider?.slice(0, 3).toUpperCase() ?? "—"}
              </span>
            )}
          </div>
          <div className="min-w-0">
            <Tooltip>
              <TooltipTrigger asChild>
                <p className="text-text-neutral-primary truncate text-sm font-semibold">
                  {findingContext.title}
                </p>
              </TooltipTrigger>
              <TooltipContent>{findingContext.title}</TooltipContent>
            </Tooltip>
            {(findingContext.resource || findingContext.provider) && (
              <p className="text-text-neutral-secondary mt-1 truncate text-xs">
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
              triage={
                isSubmitting || isManualPassDetails
                  ? { ...triage, canEdit: false }
                  : triage
              }
              value={selectedStatus}
              includeManualPass={
                triage.rawFindingStatus === FINDING_STATUS.MANUAL
              }
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

        {shouldShowManualPassProvenance && (
          <Alert variant="info">
            <AlertDescription>
              <div className="flex flex-col gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span>
                    {isPreviousManualPass
                      ? "Previous Manual Pass"
                      : MANUAL_PASS_PROVENANCE}
                    {triage.manualPassCreatedByName
                      ? ` by ${triage.manualPassCreatedByName}`
                      : ""}
                    .
                  </span>
                  {manualPassState && (
                    <Badge
                      variant={
                        manualPassState === "Active" ? "success" : "warning"
                      }
                    >
                      {manualPassState}
                    </Badge>
                  )}
                </div>
                {hasManualPassEvidence && (
                  <div className="flex flex-col gap-1">
                    <span className="font-medium">Evidence</span>
                    <p className="text-text-neutral-primary">
                      {triage.manualPassEvidence}
                    </p>
                  </div>
                )}
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <span>Attested</span>
                    <DateWithTime
                      inline
                      dateTime={triage.manualPassCreatedAt}
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <span>
                      {triage.manualPassDeactivatedAt
                        ? "Was valid until"
                        : isPreviousManualPass
                          ? "Expired on"
                          : "Valid until"}
                    </span>
                    <DateWithTime
                      inline
                      dateTime={triage.manualPassExpiresAt}
                    />
                  </div>
                  {triage.manualPassDeactivatedAt && (
                    <div className="flex items-center gap-2">
                      <span>Inactive on</span>
                      <DateWithTime
                        inline
                        dateTime={triage.manualPassDeactivatedAt}
                      />
                    </div>
                  )}
                </div>
              </div>
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
            <AlertDescription>{REMEDIATING_INFO_COPY}.</AlertDescription>
          </Alert>
        )}

        {submitError && (
          <Alert variant="error">
            <AlertDescription>{submitError}</AlertDescription>
          </Alert>
        )}

        {isManualPassDetails ? (
          <div className="flex w-full justify-end">
            <Button
              type="button"
              variant="ghost"
              size="lg"
              onClick={() => handleOpenChange(false)}
            >
              Close
            </Button>
          </div>
        ) : (
          <>
            <div className="space-y-2">
              {isManualPassSelected ? (
                <Field>
                  <FieldLabel htmlFor="finding-manual-pass-evidence">
                    Manual pass evidence
                  </FieldLabel>
                  <p
                    id="finding-manual-pass-evidence-guidance"
                    className="text-text-neutral-secondary text-sm"
                  >
                    {MANUAL_PASS_NOTE_REQUIRED_COPY}
                  </p>
                  <Textarea
                    ref={noteTextareaRef}
                    id="finding-manual-pass-evidence"
                    aria-describedby="finding-manual-pass-evidence-guidance"
                    required
                    value={manualPassEvidence}
                    maxLength={triage.maxNoteLength}
                    disabled={!canEdit}
                    textareaSize="lg"
                    onChange={(event) =>
                      setManualPassEvidence(event.target.value)
                    }
                  />
                </Field>
              ) : (
                <Textarea
                  ref={noteTextareaRef}
                  id="finding-triage-note"
                  aria-label="Note text"
                  value={note}
                  maxLength={triage.maxNoteLength}
                  disabled={!canEdit}
                  textareaSize="lg"
                  onChange={(event) => setNote(event.target.value)}
                />
              )}
              <div className="flex items-center justify-end">
                <p className="text-text-neutral-tertiary shrink-0 text-xs">
                  {isManualPassSelected
                    ? manualPassEvidence.length
                    : note.length}
                  /{triage.maxNoteLength}
                </p>
              </div>
            </div>

            {/* mt-3 lifts the gap-5 form spacing to 32px so the distance to the
                footer matches the launch scan and alert modals. */}
            <div className="mt-3 flex w-full justify-between gap-4">
              <Button
                type="button"
                variant="outline"
                size="lg"
                disabled={isSubmitting}
                onClick={() => handleOpenChange(false)}
              >
                Cancel
              </Button>
              <span className="relative inline-flex">
                {isCloudOnly && (
                  <span className="pointer-events-none absolute top-0 right-0 z-10 translate-x-1/3 -translate-y-1/2">
                    <Badge variant="cloud">Cloud</Badge>
                  </span>
                )}
                <Button
                  type={canSubmit ? "submit" : "button"}
                  size="lg"
                  aria-label={
                    isCloudOnly
                      ? "Save - available in Prowler Cloud"
                      : undefined
                  }
                  disabled={!canSubmit && !isCloudOnly}
                  onClick={
                    isCloudOnly
                      ? () =>
                          openCloudUpgrade(CLOUD_UPGRADE_FEATURE.FINDING_TRIAGE)
                      : undefined
                  }
                >
                  {isSubmitting
                    ? "Saving..."
                    : canEdit || isCloudOnly
                      ? "Save"
                      : "Unavailable"}
                </Button>
              </span>
            </div>
          </>
        )}
      </form>
    </Modal>
  );
}
