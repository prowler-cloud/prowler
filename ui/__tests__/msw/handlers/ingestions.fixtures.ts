export const INGESTION_ID = "ingestion-123";

export interface IngestionFixture {
  id: string;
  totalRecords: number;
  processedRecords: number;
  invalidRecords: number;
}

export const INGESTION_REJECTION = {
  INVALID_REPORT: "invalid-report",
  SUBSCRIPTION_REQUIRED: "subscription-required",
  PERMISSION_DENIED: "permission-denied",
  FILE_TOO_LARGE: "file-too-large",
  RATE_LIMITED: "rate-limited",
  UNEXPECTED: "unexpected",
} as const;

export type IngestionRejection =
  (typeof INGESTION_REJECTION)[keyof typeof INGESTION_REJECTION];

export interface IngestionRejectionFixture {
  status: number;
  message: string;
}

export const ingestionRejectionFixture = (
  rejection: IngestionRejection,
): IngestionRejectionFixture => {
  const fixtures = {
    [INGESTION_REJECTION.INVALID_REPORT]: {
      status: 400,
      message: "The report is not a valid Prowler OCSF finding report.",
    },
    [INGESTION_REJECTION.SUBSCRIPTION_REQUIRED]: {
      status: 402,
      message: "A Prowler Cloud subscription is required to import findings.",
    },
    [INGESTION_REJECTION.PERMISSION_DENIED]: {
      status: 403,
      message: "You do not have permission to import findings.",
    },
    [INGESTION_REJECTION.FILE_TOO_LARGE]: {
      status: 413,
      message: "The selected file exceeds the allowed upload size.",
    },
    [INGESTION_REJECTION.RATE_LIMITED]: {
      status: 429,
      message: "Too many import requests. Please try again shortly.",
    },
    [INGESTION_REJECTION.UNEXPECTED]: {
      status: 500,
      message: "Unable to start the import. Please try again.",
    },
  } as const;

  return fixtures[rejection];
};

export const ingestionFixture = (): IngestionFixture => ({
  id: INGESTION_ID,
  totalRecords: 3,
  processedRecords: 3,
  invalidRecords: 1,
});

// Stopped partway: every record read is accounted for, so the unprocessed ones
// are reported as invalid.
export const partiallyProcessedIngestionFixture = (): IngestionFixture => ({
  id: INGESTION_ID,
  totalRecords: 5,
  processedRecords: 3,
  invalidRecords: 2,
});
