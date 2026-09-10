import { FINDING_STATUS, type FindingStatus } from "@/types/components";
import {
  FINDING_TRIAGE_BILLING_HREF,
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  FINDING_TRIAGE_STATUS,
  FINDING_TRIAGE_STATUS_LABELS,
  MANUAL_PASS_PROVENANCE,
  type FindingTriageDetail,
  type FindingTriageDisabledReason,
  type FindingTriageLoadedNote,
  type FindingTriageStatus,
  type FindingTriageSummary,
  type FindingTriageUpdateResult,
} from "@/types/findings-triage";

// API/backend triage implementation is external to this UI slice. Keep final
// contract churn isolated here (and the server action transport) so table/modal
// components continue consuming stable domain DTOs.
interface FindingTriageAdapterOptions {
  canEdit?: boolean;
  disabledReason?: FindingTriageDisabledReason;
  billingHref?: string;
}

interface FindingTriageAttributes {
  finding_id?: string;
  finding_uid?: string;
  uid?: string;
  triage_id?: string;
  triage_notes_count?: number;
  notes_count?: number;
  triage_status?: unknown;
  triage_has_note?: boolean;
  status?: unknown;
  muted?: boolean;
  body?: unknown;
  current_note?: string;
  note?: string;
  has_note?: boolean;
  note_id?: string;
  raw_finding_status?: unknown;
  raw_status?: unknown;
  manual_pass_active?: unknown;
  manual_pass_evidence?: unknown;
  manual_pass_created_by_name?: unknown;
  manual_pass_created_at?: unknown;
  manual_pass_expires_at?: unknown;
  manual_pass_deactivated_at?: unknown;
}

interface JsonApiResource {
  id?: string;
  attributes?: FindingTriageAttributes;
}

interface NormalizedTriageFields {
  status: FindingTriageStatus;
  hasVisibleNote: boolean;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object";

const isJsonApiResource = (value: unknown): value is JsonApiResource =>
  isRecord(value) &&
  (!("attributes" in value) ||
    value.attributes === undefined ||
    isRecord(value.attributes));

const isFindingTriageStatus = (value: unknown): value is FindingTriageStatus =>
  typeof value === "string" &&
  Object.values(FINDING_TRIAGE_STATUS).includes(value as FindingTriageStatus);

const isRawFindingStatus = (value: unknown): value is FindingStatus =>
  typeof value === "string" &&
  Object.values(FINDING_STATUS).includes(value as FindingStatus);

const fallbackStatusFromFindingStatus = (
  findingStatus: unknown,
): FindingTriageStatus =>
  findingStatus === FINDING_STATUS.PASS
    ? FINDING_TRIAGE_STATUS.RESOLVED
    : FINDING_TRIAGE_STATUS.OPEN;

const normalizeTriageFields = (
  finding: JsonApiResource,
): NormalizedTriageFields => {
  const attributes = finding.attributes ?? {};

  if (isFindingTriageStatus(attributes.triage_status)) {
    return {
      status: attributes.triage_status,
      hasVisibleNote:
        (typeof attributes.triage_notes_count === "number" &&
          attributes.triage_notes_count >= 1) ||
        attributes.triage_has_note === true,
    };
  }

  return {
    status: fallbackStatusFromFindingStatus(attributes.status),
    hasVisibleNote: false,
  };
};

const createSummary = (
  finding: JsonApiResource,
  triageFields: NormalizedTriageFields,
  options: FindingTriageAdapterOptions,
): FindingTriageSummary => {
  const attributes = finding.attributes ?? {};
  const rawFindingStatus = isRawFindingStatus(attributes.raw_finding_status)
    ? attributes.raw_finding_status
    : isRawFindingStatus(attributes.raw_status)
      ? attributes.raw_status
      : isRawFindingStatus(attributes.status)
        ? attributes.status
        : null;
  const summary: FindingTriageSummary = {
    findingId: attributes.finding_id || finding.id || "",
    findingUid: attributes.uid || attributes.finding_uid || "",
    triageId: attributes.triage_id || null,
    notesCount: attributes.triage_notes_count ?? 0,
    status: triageFields.status,
    label: FINDING_TRIAGE_STATUS_LABELS[triageFields.status],
    hasVisibleNote: triageFields.hasVisibleNote,
    isMuted:
      typeof attributes.muted === "boolean"
        ? attributes.muted
        : attributes.status === "MUTED",
    rawFindingStatus,
    manualPassProvenance:
      attributes.status === FINDING_STATUS.PASS &&
      rawFindingStatus === FINDING_STATUS.MANUAL &&
      triageFields.status === FINDING_TRIAGE_STATUS.RESOLVED
        ? MANUAL_PASS_PROVENANCE
        : null,
    canEdit: options.canEdit ?? false,
    billingHref: options.billingHref ?? FINDING_TRIAGE_BILLING_HREF,
  };

  if (options.disabledReason) {
    summary.disabledReason = options.disabledReason;
  }

  return summary;
};

export function adaptFindingTriageSummariesResponse(
  apiResponse: unknown,
  options: FindingTriageAdapterOptions = {},
): FindingTriageSummary[] {
  if (!isRecord(apiResponse) || !Array.isArray(apiResponse.data)) {
    return [];
  }

  return apiResponse.data
    .filter(isJsonApiResource)
    .map((finding) =>
      createSummary(finding, normalizeTriageFields(finding), options),
    );
}

export function adaptLatestFindingTriageNote(
  apiResponse: unknown,
): FindingTriageLoadedNote | null {
  const latestNote =
    isRecord(apiResponse) && Array.isArray(apiResponse.data)
      ? apiResponse.data.find(isJsonApiResource)
      : undefined;
  const noteId = latestNote?.id;
  const noteBody = latestNote?.attributes?.body;

  if (typeof noteId !== "string" || !noteId || typeof noteBody !== "string") {
    return null;
  }

  return {
    noteId,
    noteBody,
  };
}

export function attachFindingTriageSummariesToResponse<
  T extends { data?: unknown },
>(
  apiResponse: T | undefined,
  options: FindingTriageAdapterOptions = {},
): T | undefined {
  if (!apiResponse || !Array.isArray(apiResponse.data)) {
    return apiResponse;
  }

  return {
    ...apiResponse,
    data: apiResponse.data.map((item) =>
      isJsonApiResource(item)
        ? {
            ...item,
            triage: createSummary(item, normalizeTriageFields(item), options),
          }
        : item,
    ),
  };
}

export function adaptFindingTriageDetailResponse(
  apiResponse: unknown,
  options: FindingTriageAdapterOptions = {},
): FindingTriageDetail {
  const data =
    isRecord(apiResponse) && isJsonApiResource(apiResponse.data)
      ? apiResponse.data
      : undefined;
  const attributes = data?.attributes ?? {};
  const status = isFindingTriageStatus(attributes.status)
    ? attributes.status
    : FINDING_TRIAGE_STATUS.OPEN;
  const noteBody =
    typeof attributes.current_note === "string"
      ? attributes.current_note
      : typeof attributes.note === "string"
        ? attributes.note
        : "";
  const notesCount =
    attributes.triage_notes_count ??
    attributes.notes_count ??
    (noteBody.length > 0 ? 1 : 0);
  const summary = createSummary(
    {
      id: attributes.finding_id || data?.id || "",
      attributes: {
        finding_uid: attributes.finding_uid || "",
        triage_id: data?.id,
        triage_notes_count: notesCount,
        raw_finding_status: attributes.raw_finding_status,
      },
    },
    {
      status,
      hasVisibleNote:
        attributes.has_note === true || notesCount > 0 || noteBody.length > 0,
    },
    options,
  );

  return {
    ...summary,
    noteId: attributes.note_id || null,
    noteBody,
    maxNoteLength: FINDING_TRIAGE_NOTE_MAX_LENGTH,
    rawFindingStatus: isRawFindingStatus(attributes.raw_finding_status)
      ? attributes.raw_finding_status
      : null,
    manualPassActive:
      typeof attributes.manual_pass_active === "boolean"
        ? attributes.manual_pass_active
        : null,
    manualPassEvidence:
      typeof attributes.manual_pass_evidence === "string"
        ? attributes.manual_pass_evidence
        : null,
    manualPassCreatedByName:
      typeof attributes.manual_pass_created_by_name === "string"
        ? attributes.manual_pass_created_by_name
        : null,
    manualPassCreatedAt:
      typeof attributes.manual_pass_created_at === "string"
        ? attributes.manual_pass_created_at
        : null,
    manualPassExpiresAt:
      typeof attributes.manual_pass_expires_at === "string"
        ? attributes.manual_pass_expires_at
        : null,
    manualPassDeactivatedAt:
      typeof attributes.manual_pass_deactivated_at === "string"
        ? attributes.manual_pass_deactivated_at
        : null,
  };
}

export function adaptFindingTriageUpdateResponse(
  apiResponse: unknown,
): FindingTriageUpdateResult {
  const data =
    isRecord(apiResponse) && isJsonApiResource(apiResponse.data)
      ? apiResponse.data
      : undefined;
  const expiresAt = data?.attributes?.manual_pass_expires_at;

  return {
    manualPassExpiresAt: typeof expiresAt === "string" ? expiresAt : null,
  };
}
