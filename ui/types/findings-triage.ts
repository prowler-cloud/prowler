export const FINDING_TRIAGE_STATUS = {
  OPEN: "open",
  UNDER_REVIEW: "under_review",
  REMEDIATING: "remediating",
  RESOLVED: "resolved",
  RISK_ACCEPTED: "risk_accepted",
  FALSE_POSITIVE: "false_positive",
  REOPENED: "reopened",
} as const;

export type FindingTriageStatus =
  (typeof FINDING_TRIAGE_STATUS)[keyof typeof FINDING_TRIAGE_STATUS];

export const FINDING_TRIAGE_STATUS_LABELS = {
  [FINDING_TRIAGE_STATUS.OPEN]: "Open",
  [FINDING_TRIAGE_STATUS.UNDER_REVIEW]: "Under Review",
  [FINDING_TRIAGE_STATUS.REMEDIATING]: "Remediating",
  [FINDING_TRIAGE_STATUS.RESOLVED]: "Resolved",
  [FINDING_TRIAGE_STATUS.RISK_ACCEPTED]: "Risk Accepted",
  [FINDING_TRIAGE_STATUS.FALSE_POSITIVE]: "False Positive",
  [FINDING_TRIAGE_STATUS.REOPENED]: "Reopened",
} as const satisfies Record<FindingTriageStatus, string>;

export const FINDING_TRIAGE_MANUAL_STATUS_VALUES = [
  FINDING_TRIAGE_STATUS.OPEN,
  FINDING_TRIAGE_STATUS.UNDER_REVIEW,
  FINDING_TRIAGE_STATUS.REMEDIATING,
  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
  FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
] as const;

export type FindingTriageManualStatus =
  (typeof FINDING_TRIAGE_MANUAL_STATUS_VALUES)[number];

export const FINDING_TRIAGE_AUTOMATION_STATUS_VALUES = [
  FINDING_TRIAGE_STATUS.RESOLVED,
  FINDING_TRIAGE_STATUS.REOPENED,
] as const;

export const FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES = [
  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
  FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
] as const;

export const isManualStatus = (
  status: unknown,
): status is FindingTriageManualStatus => {
  return FINDING_TRIAGE_MANUAL_STATUS_VALUES.some((value) => value === status);
};

export const isMutelistShortcutStatus = (status: unknown): boolean => {
  return FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES.some(
    (value) => value === status,
  );
};

export const getFindingTriageMuteInfoCopy = (status: FindingTriageStatus) =>
  `Changing triage to ${FINDING_TRIAGE_STATUS_LABELS[status]} will mute the finding`;

// Only RESOLVED locks manual edits: automation owns the transition out of it
// (REOPENED on a failing rescan), while REOPENED invites human re-triage.
export const isTriageStatusLocked = (status: FindingTriageStatus): boolean =>
  status === FINDING_TRIAGE_STATUS.RESOLVED;

export const FINDING_TRIAGE_RESOLVED_LOCKED_COPY =
  "Triage status is managed automatically once the finding is resolved." as const;

export const FINDING_TRIAGE_DISABLED_REASON = {
  CLOUD_ONLY: "cloud_only",
  FORBIDDEN: "forbidden",
  LOADING: "loading",
} as const;

export type FindingTriageDisabledReason =
  (typeof FINDING_TRIAGE_DISABLED_REASON)[keyof typeof FINDING_TRIAGE_DISABLED_REASON];

export const FINDING_TRIAGE_ORIGIN = {
  TABLE: "table",
  MODAL: "modal",
} as const;

export const FINDING_TRIAGE_NOTE_MAX_LENGTH = 500 as const;
export const FINDING_TRIAGE_BILLING_HREF =
  "https://prowler.com/pricing" as const;

export interface FindingTriageSummary {
  findingId: string;
  findingUid: string;
  triageId: string | null;
  notesCount: number;
  status: FindingTriageStatus;
  label: string;
  hasVisibleNote: boolean;
  isMuted: boolean;
  canEdit: boolean;
  disabledReason?: FindingTriageDisabledReason;
  billingHref: string;
}

export interface FindingTriageDetail extends FindingTriageSummary {
  noteId: string | null;
  noteBody: string;
  maxNoteLength: typeof FINDING_TRIAGE_NOTE_MAX_LENGTH;
}

export interface UpdateFindingTriageInput {
  findingId: string;
  findingUid: string;
  triageId: string | null;
  notesCount: number;
  noteId?: string | null;
  status?: FindingTriageManualStatus;
  previousStatus?: FindingTriageStatus;
  isMuted?: boolean;
  note?: string;
}

export interface FindingTriageLoadedNote {
  noteId: string;
  noteBody: string;
}
