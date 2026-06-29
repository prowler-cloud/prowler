import {
  FINDING_TRIAGE_BILLING_HREF,
  FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES,
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  FINDING_TRIAGE_NOTE_PRIVACY_COPY,
  FINDING_TRIAGE_STATUS,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageDetail,
  type FindingTriageDisabledReason,
  type FindingTriageStatus,
  type FindingTriageSummary,
} from "@/types/findings-triage";

// API/backend triage implementation is external to this UI slice. Keep final
// contract churn isolated here (and the server action transport) so table/modal
// components continue consuming stable domain DTOs.
interface FindingTriageAdapterOptions {
  canEdit?: boolean;
  disabledReason?: FindingTriageDisabledReason;
  billingHref?: string;
}

interface JsonApiResource {
  type?: string;
  id?: string;
  attributes?: Record<string, unknown>;
  relationships?: Record<string, unknown>;
}

interface JsonApiResponse {
  data: JsonApiResource | JsonApiResource[];
  included?: JsonApiResource[];
}

interface NormalizedTriageFields {
  status: FindingTriageStatus;
  hasVisibleNote: boolean;
  hasPersistedStatus: boolean;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object";

const isJsonApiResource = (value: unknown): value is JsonApiResource =>
  isRecord(value);

const isJsonApiResponse = (value: unknown): value is JsonApiResponse => {
  if (!isRecord(value) || !("data" in value)) {
    return false;
  }

  const data = value.data;
  return Array.isArray(data) || isJsonApiResource(data);
};

const toResourceArray = (data: JsonApiResponse["data"]): JsonApiResource[] =>
  Array.isArray(data) ? data : [data];

const asString = (value: unknown): string | undefined =>
  typeof value === "string" && value.length > 0 ? value : undefined;

const asBoolean = (value: unknown): boolean => value === true;

const asNumber = (value: unknown): number | undefined =>
  typeof value === "number" && Number.isFinite(value) ? value : undefined;

const hasPositiveCount = (value: unknown): boolean =>
  typeof value === "number" && value >= 1;

const isFindingTriageStatus = (value: unknown): value is FindingTriageStatus =>
  typeof value === "string" &&
  Object.values(FINDING_TRIAGE_STATUS).includes(value as FindingTriageStatus);

const getRelationshipData = (
  resource: JsonApiResource,
  relationshipName: string,
): JsonApiResource | undefined => {
  const relationship = resource.relationships?.[relationshipName];

  if (!isRecord(relationship)) {
    return undefined;
  }

  const data = relationship.data;
  return isJsonApiResource(data) ? data : undefined;
};

const createIncludedLookup = (
  included: JsonApiResource[] | undefined,
): Record<string, JsonApiResource> => {
  const lookup: Record<string, JsonApiResource> = {};

  for (const item of included ?? []) {
    if (!item.type || !item.id) {
      continue;
    }

    lookup[`${item.type}:${item.id}`] = item;
  }

  return lookup;
};

const findIncludedTriage = (
  finding: JsonApiResource,
  includedLookup: Record<string, JsonApiResource>,
): JsonApiResource | undefined => {
  const triageRelationship = getRelationshipData(finding, "triage");

  if (!triageRelationship?.type || !triageRelationship.id) {
    return undefined;
  }

  return includedLookup[`${triageRelationship.type}:${triageRelationship.id}`];
};

const fallbackStatusFromFindingStatus = (
  findingStatus: unknown,
): FindingTriageStatus =>
  findingStatus === "PASS"
    ? FINDING_TRIAGE_STATUS.RESOLVED
    : FINDING_TRIAGE_STATUS.OPEN;

const normalizeTriageFields = (
  finding: JsonApiResource,
  includedTriage?: JsonApiResource,
): NormalizedTriageFields => {
  const findingAttributes = finding.attributes ?? {};
  const includedAttributes = includedTriage?.attributes ?? {};
  const flatStatus = findingAttributes.triage_status;
  const includedStatus =
    includedAttributes.status ?? includedAttributes.triage_status;

  if (isFindingTriageStatus(flatStatus)) {
    return {
      status: flatStatus,
      hasVisibleNote:
        hasPositiveCount(findingAttributes.triage_notes_count) ||
        asBoolean(findingAttributes.triage_has_note) ||
        asBoolean(includedAttributes.has_note) ||
        asBoolean(includedAttributes.triage_has_note),
      hasPersistedStatus: true,
    };
  }

  if (isFindingTriageStatus(includedStatus)) {
    return {
      status: includedStatus,
      hasVisibleNote:
        hasPositiveCount(includedAttributes.triage_notes_count) ||
        asBoolean(includedAttributes.has_note) ||
        asBoolean(includedAttributes.triage_has_note),
      hasPersistedStatus: true,
    };
  }

  return {
    status: fallbackStatusFromFindingStatus(findingAttributes.status),
    hasVisibleNote: false,
    hasPersistedStatus: false,
  };
};

const createSummary = (
  finding: JsonApiResource,
  triageFields: NormalizedTriageFields,
  options: FindingTriageAdapterOptions,
): FindingTriageSummary => {
  const attributes = finding.attributes ?? {};
  const summary: FindingTriageSummary = {
    findingId: asString(attributes.finding_id) ?? finding.id ?? "",
    findingUid:
      asString(attributes.uid) ?? asString(attributes.finding_uid) ?? "",
    triageId: asString(attributes.triage_id) ?? null,
    notesCount: asNumber(attributes.triage_notes_count) ?? 0,
    status: triageFields.status,
    label: FINDING_TRIAGE_STATUS_LABELS[triageFields.status],
    hasVisibleNote: triageFields.hasVisibleNote,
    hasPersistedStatus: triageFields.hasPersistedStatus,
    isMuted:
      typeof attributes.muted === "boolean"
        ? attributes.muted
        : attributes.status === "MUTED",
    canEdit: options.canEdit ?? false,
    billingHref: options.billingHref ?? FINDING_TRIAGE_BILLING_HREF,
    mutelistShortcutStatuses: FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES,
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
  if (!isJsonApiResponse(apiResponse) || !Array.isArray(apiResponse.data)) {
    return [];
  }

  const includedLookup = createIncludedLookup(apiResponse.included);

  return toResourceArray(apiResponse.data)
    .filter(isJsonApiResource)
    .map((finding) =>
      createSummary(
        finding,
        normalizeTriageFields(
          finding,
          findIncludedTriage(finding, includedLookup),
        ),
        options,
      ),
    );
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

  const triageSummaries = adaptFindingTriageSummariesResponse(
    apiResponse,
    options,
  );

  return {
    ...apiResponse,
    data: apiResponse.data.map((item, index) =>
      isJsonApiResource(item)
        ? { ...item, triage: triageSummaries[index] }
        : item,
    ),
  };
}

export function adaptFindingTriageDetailResponse(
  apiResponse: unknown,
  options: FindingTriageAdapterOptions = {},
): FindingTriageDetail {
  const data =
    isJsonApiResponse(apiResponse) && isJsonApiResource(apiResponse.data)
      ? apiResponse.data
      : undefined;
  const attributes = data?.attributes ?? {};
  const status = isFindingTriageStatus(attributes.status)
    ? attributes.status
    : FINDING_TRIAGE_STATUS.OPEN;
  const noteBody =
    asString(attributes.current_note) ?? asString(attributes.note) ?? "";
  const summary = createSummary(
    {
      id: asString(attributes.finding_id) ?? data?.id ?? "",
      attributes: {
        finding_uid: asString(attributes.finding_uid) ?? "",
        triage_id: data?.id,
        triage_notes_count:
          asNumber(attributes.triage_notes_count) ??
          (noteBody.length > 0 ? 1 : 0),
      },
    },
    {
      status,
      hasVisibleNote: asBoolean(attributes.has_note) || noteBody.length > 0,
      hasPersistedStatus: data !== undefined,
    },
    options,
  );

  return {
    ...summary,
    noteId: asString(attributes.note_id) ?? null,
    noteBody,
    maxNoteLength: FINDING_TRIAGE_NOTE_MAX_LENGTH,
    privacyCopy: FINDING_TRIAGE_NOTE_PRIVACY_COPY,
  };
}
