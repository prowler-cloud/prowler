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

export type FindingTriageAutomationStatus =
  (typeof FINDING_TRIAGE_AUTOMATION_STATUS_VALUES)[number];

export const FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES = [
  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
  FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
] as const;

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

export type FindingTriageOrigin =
  (typeof FINDING_TRIAGE_ORIGIN)[keyof typeof FINDING_TRIAGE_ORIGIN];

export const FINDING_TRIAGE_NOTE_MAX_LENGTH = 500 as const;
export const FINDING_TRIAGE_NOTE_PRIVACY_COPY =
  "This note is only visible to your team." as const;
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
  hasPersistedStatus: boolean;
  isMuted: boolean;
  canEdit: boolean;
  disabledReason?: FindingTriageDisabledReason;
  billingHref: string;
  mutelistShortcutStatuses: readonly FindingTriageStatus[];
}

export interface FindingTriageDetail extends FindingTriageSummary {
  noteId: string | null;
  noteBody: string;
  maxNoteLength: typeof FINDING_TRIAGE_NOTE_MAX_LENGTH;
  privacyCopy: typeof FINDING_TRIAGE_NOTE_PRIVACY_COPY;
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
  origin: FindingTriageOrigin;
}

export interface FindingTriageLoadedNote {
  noteId: string;
  noteBody: string;
}
