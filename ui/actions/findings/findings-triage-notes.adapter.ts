import type { FindingTriageLoadedNote } from "@/types/findings-triage";

interface JsonApiResource {
  id?: string;
  attributes?: Record<string, unknown>;
}

interface JsonApiResponse {
  data?: JsonApiResource | JsonApiResource[];
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object";

const asString = (value: unknown): string | undefined =>
  typeof value === "string" && value.length > 0 ? value : undefined;

const toResourceArray = (data: JsonApiResponse["data"]): JsonApiResource[] => {
  if (Array.isArray(data)) {
    return data;
  }

  return data ? [data] : [];
};

export function adaptLatestFindingTriageNote(
  apiResponse: unknown,
): FindingTriageLoadedNote | null {
  if (!isRecord(apiResponse)) {
    return null;
  }

  const [latestNote] = toResourceArray((apiResponse as JsonApiResponse).data);
  const noteId = asString(latestNote?.id);
  const noteBody = asString(latestNote?.attributes?.body);

  if (!noteId || noteBody === undefined) {
    return null;
  }

  return {
    noteId,
    noteBody,
  };
}
