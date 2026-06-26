"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { PROVIDER_BADGE_BY_NAME } from "@/components/icons/providers-badge";
import { Button, Textarea } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import {
  Select,
  SelectContent,
  SelectItem,
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
import { PROVIDER_DISPLAY_NAMES, type ProviderType } from "@/types/providers";

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

const TRIAGE_STATUS_STYLE = {
  open: "border-orange-600/70 bg-orange-950/40 text-orange-400 [&_svg]:text-orange-400",
  under_review:
    "border-yellow-600/70 bg-yellow-950/40 text-yellow-400 [&_svg]:text-yellow-400",
  remediating:
    "border-blue-600/70 bg-blue-950/40 text-blue-400 [&_svg]:text-blue-400",
  resolved:
    "border-emerald-600/70 bg-emerald-950/40 text-emerald-400 [&_svg]:text-emerald-400",
  risk_accepted:
    "border-purple-600/70 bg-purple-950/40 text-purple-400 [&_svg]:text-purple-400",
  false_positive:
    "border-purple-600/70 bg-purple-950/40 text-purple-400 [&_svg]:text-purple-400",
  reopened:
    "border-orange-600/70 bg-orange-950/40 text-orange-400 [&_svg]:text-orange-400",
} as const satisfies Record<FindingTriageStatus, string>;

const TRIAGE_STATUS_TEXT_STYLE = {
  open: "text-orange-400",
  under_review: "text-yellow-400",
  remediating: "text-blue-400",
  resolved: "text-emerald-400",
  risk_accepted: "text-purple-400",
  false_positive: "text-purple-400",
  reopened: "text-orange-400",
} as const satisfies Record<FindingTriageStatus, string>;

const TRIAGE_STATUS_DOT_STYLE = {
  open: "bg-orange-400",
  under_review: "bg-yellow-400",
  remediating: "bg-blue-400",
  resolved: "bg-emerald-400",
  risk_accepted: "bg-purple-400",
  false_positive: "bg-purple-400",
  reopened: "bg-orange-400",
} as const satisfies Record<FindingTriageStatus, string>;

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
        size="sm"
        iconSize="sm"
        className={`${TRIAGE_STATUS_STYLE[value]} ${
          variant === "modal"
            ? "!h-8 !w-auto min-w-28 border-0 bg-transparent px-2 py-0 shadow-none hover:bg-transparent focus-visible:ring-0 focus-visible:ring-offset-0"
            : "!h-8 !w-fit max-w-40 !min-w-0 rounded-lg !px-3 !py-0 text-xs font-semibold"
        }`}
      >
        <span className="truncate">{getVisibleStatusLabel(value)}</span>
      </SelectTrigger>
      <SelectContent>
        {FINDING_TRIAGE_MANUAL_STATUS_VALUES.map((status) => (
          <SelectItem key={status} value={status}>
            <span
              className={`${TRIAGE_STATUS_DOT_STYLE[status]} size-2 rounded-full`}
              aria-hidden="true"
            />
            <span className={TRIAGE_STATUS_TEXT_STYLE[status]}>
              {FINDING_TRIAGE_STATUS_LABELS[status]}
            </span>
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
    triage.canEdit && Boolean(props.onTriageUpdateAction);

  const handleTableValueChange = (status: FindingTriageManualStatus) => {
    if (!props.onTriageUpdateAction) {
      return;
    }

    if (isMutelistShortcutStatus(status)) {
      setPendingMutelistStatus(status);
      return;
    }

    setSelectedStatus(status);
    props.onTriageUpdateAction({
      findingId: triage.findingId,
      status,
      origin: "table",
    });
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

    setSelectedStatus(pendingMutelistStatus);
    props.onTriageUpdateAction({
      findingId: triage.findingId,
      status: pendingMutelistStatus,
      origin: "table",
    });
    setPendingMutelistStatus(null);
  };

  return (
    <>
      <TriageStatusSelect
        disabled={!canMutateFromTable}
        value={selectedStatus}
        onValueChange={handleTableValueChange}
      />
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
  const canSubmit = triage.canEdit && Boolean(onTriageUpdateAction);
  const isCloudOnly =
    triage.disabledReason === FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY;
  const shouldShowMutelistInfo =
    canSubmit && isMutelistShortcutStatus(selectedStatus);
  const providerDisplayName = findingContext.providerType
    ? PROVIDER_DISPLAY_NAMES[findingContext.providerType]
    : findingContext.provider;
  const ProviderBadge = providerDisplayName
    ? PROVIDER_BADGE_BY_NAME[providerDisplayName]
    : undefined;

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!canSubmit) {
      if (isCloudOnly) {
        router.push(triage.billingHref);
      }
      return;
    }

    onTriageUpdateAction?.({
      findingId: triage.findingId,
      ...(isManualStatus(selectedStatus) ? { status: selectedStatus } : {}),
      note,
      origin: "modal",
    });
    onOpenChange(false);
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
            {ProviderBadge ? (
              <ProviderBadge width={22} height={22} />
            ) : (
              <span className="text-xs font-semibold text-red-500">
                {providerDisplayName?.slice(0, 3).toUpperCase() ?? "—"}
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
          <span
            className={`${TRIAGE_STATUS_DOT_STYLE[selectedStatus]} size-2 rounded-full`}
            aria-hidden="true"
          />
          <FindingTriageStatusControl
            origin={FINDING_TRIAGE_ORIGIN.MODAL}
            triage={triage}
            value={selectedStatus}
            onValueChange={setSelectedStatus}
          />
        </div>

        {shouldShowMutelistInfo && (
          <div className="rounded-lg border border-orange-500/50 bg-orange-500/10 p-3 text-sm text-orange-300">
            This finding will be muted through the existing Mutelist flow.
          </div>
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
            {canSubmit
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
