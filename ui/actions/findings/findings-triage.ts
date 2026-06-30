"use server";

import { adaptLatestFindingTriageNote } from "@/actions/findings/findings-triage.adapter";
import { createMuteRule } from "@/actions/mute-rules";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import {
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageLoadedNote,
  type FindingTriageSummary,
  isMutelistShortcutStatus,
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

const buildApiUrl = (path: `/${string}`) => {
  if (!apiBaseUrl) {
    throw new Error("API base URL is not configured.");
  }

  const url = new URL(apiBaseUrl);
  url.pathname = `${url.pathname.replace(/\/$/, "")}${path}`;
  return url.toString();
};

async function getJsonApi(path: `/${string}`) {
  const headers = await getAuthHeaders({ contentType: false });
  const response = await fetch(buildApiUrl(path), {
    headers,
  });

  return handleApiResponse(response);
}

const throwIfApiError = (result: unknown) => {
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
};

async function patchJsonApi(path: `/${string}`, body: unknown) {
  const headers = await getAuthHeaders({ contentType: false });
  const response = await fetch(buildApiUrl(path), {
    method: "PATCH",
    headers: {
      ...headers,
      "Content-Type": JSON_API_CONTENT_TYPE,
    },
    body: JSON.stringify(body),
  });

  const result = await handleApiResponse(response);
  throwIfApiError(result);
  return result;
}

async function deleteJsonApi(path: `/${string}`) {
  const headers = await getAuthHeaders({ contentType: false });
  const response = await fetch(buildApiUrl(path), {
    method: "DELETE",
    headers,
  });

  const result = await handleApiResponse(response);
  throwIfApiError(result);
  return result;
}

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
      `/finding-triages/${input.triageId}`,
      buildFindingTriageBody({ status: previousStatus }),
    );
    return;
  }

  if (findingUid) {
    await patchJsonApi(
      `/findings/${encodePathSegment(findingUid)}/triage`,
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

  const apiResponse = await getJsonApi(
    `/findings/${encodePathSegment(findingId)}`,
  );
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
      ? `/finding-triages/${triage.triageId}/notes`
      : `/findings/${encodePathSegment(findingUid)}/triage/notes`,
  );
  const latestNote = adaptLatestFindingTriageNote(apiResponse);

  if (!latestNote) {
    throw new Error("Could not load the latest finding triage note.");
  }

  return latestNote;
}

export async function updateFindingTriage(input: UpdateFindingTriageInput) {
  let findingUid: string | undefined;
  let triagePath: `/${string}`;

  if (input.triageId) {
    triagePath = `/finding-triages/${input.triageId}`;
  } else {
    findingUid = await resolveFindingUid(input);
    triagePath = `/findings/${encodePathSegment(findingUid)}/triage`;
  }

  if (input.note !== undefined && input.notesCount > 0 && input.noteId) {
    const notePath: `/${string}` = `${triagePath}/notes/${input.noteId}`;
    const noteResult =
      input.note === ""
        ? await deleteJsonApi(notePath)
        : await patchJsonApi(notePath, buildFindingTriageNoteBody(input.note));

    if (!input.status) {
      return noteResult;
    }
  }

  if (!input.status && !(input.note && input.notesCount === 0)) {
    return undefined;
  }

  const result = await patchJsonApi(
    triagePath,
    buildFindingTriageBody({
      status: input.status,
      note: input.notesCount === 0 && input.note ? input.note : undefined,
    }),
  );
  await createMuteRuleOrRollback(input, findingUid);
  return result;
}
