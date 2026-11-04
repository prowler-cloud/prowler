// Client code imports guards from here: sample-records pulls in the whole dataset.
// Sample records have a reserved prefix; real API record IDs are UUIDs.
export const SAMPLE_ID_PREFIX = "sample-";

export const isSampleId = (
  id: string | undefined | null,
): id is `sample-${string}` =>
  typeof id === "string" && id.startsWith(SAMPLE_ID_PREFIX);

export const SAMPLE_DATA_READ_ONLY_MESSAGE =
  "Sample data is read-only. Connect your cloud account and complete a scan to use this action.";

export const SAMPLE_WRITE_MESSAGE =
  "This is sample data, so nothing was saved. Connect your cloud account to work on your own findings.";
