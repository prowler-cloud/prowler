export const INGESTION_STATUS = {
  PENDING: "pending",
  PROCESSING: "processing",
  COMPLETED: "completed",
  FAILED: "failed",
} as const;

export type IngestionStatus =
  (typeof INGESTION_STATUS)[keyof typeof INGESTION_STATUS];

export interface Ingestion {
  id: string;
  status: IngestionStatus;
  totalRecords: number;
  processedRecords: number;
  invalidRecords: number;
}

export interface IngestionResponse {
  data: Ingestion;
}
