import type { FindingTriageLoadedNote } from "@/types/findings-triage";

export function adaptLatestFindingTriageNote(
  apiResponse: unknown,
): FindingTriageLoadedNote | null {
  const latestNote = (apiResponse as { data?: unknown[] })?.data?.[0] as
    | { id?: unknown; attributes?: { body?: unknown } }
    | undefined;

  if (
    typeof latestNote?.id !== "string" ||
    typeof latestNote.attributes?.body !== "string"
  ) {
    return null;
  }

  return {
    noteId: latestNote.id,
    noteBody: latestNote.attributes.body,
  };
}
