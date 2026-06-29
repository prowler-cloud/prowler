"use server";

import { adaptLatestFindingTriageNote } from "@/actions/findings/findings-triage-notes.adapter";
import { createMuteRule } from "@/actions/mute-rules";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import {
  FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageLoadedNote,
  type FindingTriageSummary,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

const JSON_API_CONTENT_TYPE = "application/vnd.api+json";

const buildFindingTriageBody = ({
  status,
  note,
}: {
  status?:
    | UpdateFindingTriageInput["status"]
    | UpdateFindingTriageInput["previousStatus"];
  note?: UpdateFindingTriageInput["note"];
}) => ({
  data: {
    type: "finding-triages",
    attributes: {
      ...(status ? { status } : {}),
      ...(note ? { note } : {}),
    },
  },
});

const buildFindingTriageNoteBody = (body: string) => ({
  data: {
    type: "finding-triage-notes",
    attributes: {
      body,
    },
  },
});

async function getJsonApi(url: string) {
  const headers = await getAuthHeaders({ contentType: false });
  const response = await fetch(url, {
    headers,
  });

  return handleApiResponse(response);
}

async function patchJsonApi(url: string, body: unknown) {
  const headers = await getAuthHeaders({ contentType: false });
  const response = await fetch(url, {
    method: "PATCH",
    headers: {
      ...headers,
      "Content-Type": JSON_API_CONTENT_TYPE,
    },
    body: JSON.stringify(body),
  });

  const result = await handleApiResponse(response);

  if (
    result &&
    typeof result === "object" &&
    ("error" in result ||
      ("status" in result &&
        typeof result.status === "number" &&
        result.status >= 400))
  ) {
    throw new Error(
      "error" in result && typeof result.error === "string"
        ? result.error
        : "Finding triage request failed.",
    );
  }

  return result;
}

const isMutelistShortcutStatus = (
  status:
    | UpdateFindingTriageInput["status"]
    | UpdateFindingTriageInput["previousStatus"],
) =>
  Boolean(status) &&
  FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES.some(
    (shortcutStatus) => shortcutStatus === status,
  );

const shouldCreateTriageMuteRule = (
  input: UpdateFindingTriageInput,
): input is UpdateFindingTriageInput & {
  status: NonNullable<UpdateFindingTriageInput["status"]>;
} =>
  Boolean(input.status) &&
  input.previousStatus !== undefined &&
  input.status !== input.previousStatus &&
  input.isMuted !== true &&
  isMutelistShortcutStatus(input.status) &&
  !isMutelistShortcutStatus(input.previousStatus);

async function createTriageMuteRule(input: UpdateFindingTriageInput) {
  if (!shouldCreateTriageMuteRule(input)) {
    return;
  }

  const label = FINDING_TRIAGE_STATUS_LABELS[input.status];
  const formData = new FormData();
  formData.set("name", `Finding triage: ${label} - ${input.findingId}`);
  formData.set("reason", `Finding triage status changed to ${label}.`);
  formData.set("finding_ids", JSON.stringify([input.findingId]));

  const result = await createMuteRule(null, formData);

  if (result?.errors) {
    throw new Error(
      result.errors.general ||
        result.errors.finding_ids ||
        result.errors.name ||
        result.errors.reason ||
        "Could not mute finding after triage status change.",
    );
  }
}

const encodePathSegment = (value: string) => encodeURIComponent(value);

async function rollbackTriageStatus(
  input: UpdateFindingTriageInput,
  findingUid?: string,
) {
  if (!input.previousStatus || !shouldCreateTriageMuteRule(input)) {
    return;
  }

  const previousStatus = input.previousStatus;

  if (input.triageId) {
    await patchJsonApi(
      `${apiBaseUrl}/finding-triages/${input.triageId}`,
      buildFindingTriageBody({ status: previousStatus }),
    );
    return;
  }

  if (findingUid) {
    await patchJsonApi(
      `${apiBaseUrl}/findings/${encodePathSegment(findingUid)}/triage`,
      buildFindingTriageBody({ status: previousStatus }),
    );
  }
}

async function createMuteRuleOrRollback(
  input: UpdateFindingTriageInput,
  findingUid?: string,
) {
  try {
    await createTriageMuteRule(input);
  } catch (error) {
    try {
      await rollbackTriageStatus(input, findingUid);
    } catch (rollbackError) {
      console.error("Could not rollback finding triage status.", rollbackError);
    }
    throw error;
  }
}

async function resolveFindingUid({
  findingId,
  findingUid,
}: Pick<UpdateFindingTriageInput, "findingId" | "findingUid">) {
  if (findingUid) {
    return findingUid;
  }

  const apiResponse = await getJsonApi(`${apiBaseUrl}/findings/${findingId}`);
  const resolvedFindingUid = apiResponse?.data?.attributes?.uid;

  if (typeof resolvedFindingUid !== "string" || !resolvedFindingUid) {
    throw new Error("Cannot create finding triage without findingUid.");
  }

  return resolvedFindingUid;
}

export async function loadLatestFindingTriageNote(
  triage: FindingTriageSummary,
): Promise<FindingTriageLoadedNote> {
  const findingUid = triage.triageId
    ? triage.findingUid
    : await resolveFindingUid(triage);
  const apiResponse = await getJsonApi(
    triage.triageId
      ? `${apiBaseUrl}/finding-triages/${triage.triageId}/notes`
      : `${apiBaseUrl}/findings/${encodePathSegment(findingUid)}/triage/notes`,
  );
  const latestNote = adaptLatestFindingTriageNote(apiResponse);

  if (!latestNote) {
    throw new Error("Could not load the latest finding triage note.");
  }

  return latestNote;
}

export async function updateFindingTriage(input: UpdateFindingTriageInput) {
  if (input.triageId) {
    if (input.note && input.notesCount > 0 && input.noteId) {
      await patchJsonApi(
        `${apiBaseUrl}/finding-triages/${input.triageId}/notes/${input.noteId}`,
        buildFindingTriageNoteBody(input.note),
      );
    }

    if (input.status || (input.note && input.notesCount === 0)) {
      const result = await patchJsonApi(
        `${apiBaseUrl}/finding-triages/${input.triageId}`,
        buildFindingTriageBody({
          status: input.status,
          note: input.notesCount === 0 ? input.note : undefined,
        }),
      );
      await createMuteRuleOrRollback(input);
      return result;
    }

    return undefined;
  }

  const findingUid = await resolveFindingUid(input);

  if (input.note && input.notesCount > 0 && input.noteId) {
    const noteResult = await patchJsonApi(
      `${apiBaseUrl}/findings/${encodePathSegment(findingUid)}/triage/notes/${input.noteId}`,
      buildFindingTriageNoteBody(input.note),
    );

    if (!input.status) {
      return noteResult;
    }
  }

  const result = await patchJsonApi(
    `${apiBaseUrl}/findings/${encodePathSegment(findingUid)}/triage`,
    buildFindingTriageBody({
      status: input.status,
      note: input.notesCount === 0 ? input.note : undefined,
    }),
  );
  await createMuteRuleOrRollback(input, findingUid);
  return result;
}
