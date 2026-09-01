import {
  INGESTION_STATUS,
  type Ingestion,
  type IngestionStatus,
} from "@/types";

interface JsonApiIngestionSummary {
  total?: unknown;
  processed?: unknown;
  invalid?: unknown;
}

interface JsonApiIngestionAttributes {
  status?: unknown;
  summary?: JsonApiIngestionSummary;
}

interface JsonApiIngestionData {
  id?: unknown;
  attributes?: JsonApiIngestionAttributes;
}

interface JsonApiIngestionResponse {
  data?: JsonApiIngestionData;
}

const isIngestionStatus = (value: unknown): value is IngestionStatus =>
  Object.values(INGESTION_STATUS).includes(value as IngestionStatus);

// Counts are absent until the job reports them: read as 0, not a failure.
const recordCount = (value: unknown): number =>
  typeof value === "number" ? value : 0;

export const parseIngestion = (payload: unknown): Ingestion | null => {
  const data = (payload as JsonApiIngestionResponse)?.data;
  const attributes = data?.attributes;

  if (
    typeof data?.id !== "string" ||
    data.id === "" ||
    !isIngestionStatus(attributes?.status)
  ) {
    return null;
  }

  const summary = attributes.summary;

  return {
    id: data.id,
    status: attributes.status,
    totalRecords: recordCount(summary?.total),
    processedRecords: recordCount(summary?.processed),
    invalidRecords: recordCount(summary?.invalid),
  };
};
