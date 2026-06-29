"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";

const JSON_API_CONTENT_TYPE = "application/vnd.api+json";

const buildFindingTriageBody = ({
  status,
  note,
}: Pick<UpdateFindingTriageInput, "status" | "note">) => ({
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

  return handleApiResponse(response);
}

export async function updateFindingTriage(input: UpdateFindingTriageInput) {
  if (input.triageId) {
    if (input.note && input.notesCount > 0 && input.noteId) {
      await patchJsonApi(
        `${apiBaseUrl}/finding-triages/${input.triageId}/notes/${input.noteId}`,
        buildFindingTriageNoteBody(input.note),
      );
    }

    if (input.status) {
      return patchJsonApi(
        `${apiBaseUrl}/finding-triages/${input.triageId}`,
        buildFindingTriageBody({ status: input.status }),
      );
    }

    return undefined;
  }

  if (!input.findingUid) {
    throw new Error("Cannot create finding triage without findingUid.");
  }

  return patchJsonApi(
    `${apiBaseUrl}/findings/${input.findingUid}/triage`,
    buildFindingTriageBody({ status: input.status, note: input.note }),
  );
}
