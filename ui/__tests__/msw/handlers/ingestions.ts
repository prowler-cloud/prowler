import { delay, http, HttpResponse } from "msw";

import type {
  IngestionFixture,
  IngestionRejectionFixture,
} from "./ingestions.fixtures";

const API = "/api/ingestions";

// A job only reports its record counters once it reaches a terminal status —
// `failed` included, which is how a partially processed import is told apart
// from one that landed nothing.
const ingestionResponse = (
  fixture: IngestionFixture,
  status: "pending" | "processing" | "completed" | "failed",
) => {
  const terminal = status === "completed" || status === "failed";
  return {
    data: {
      id: fixture.id,
      status,
      totalRecords: fixture.totalRecords,
      processedRecords: terminal ? fixture.processedRecords : 0,
      invalidRecords: terminal ? fixture.invalidRecords : 0,
    },
  };
};

/** A successful upload advances through the API's asynchronous job states. */
interface IngestionHandlerOptions {
  uploadRejection?: IngestionRejectionFixture;
  uploadDelayMs?: number;
  statusErrorAt?: number;
  statusDelayMs?: number;
  statusSequence?: Array<"processing" | "completed" | "failed">;
  onStatusRequest?: (inFlight: number) => void;
}

export const handlersForIngestion = (
  fixture: IngestionFixture,
  {
    uploadRejection,
    uploadDelayMs,
    statusErrorAt,
    statusDelayMs,
    statusSequence,
    onStatusRequest,
  }: IngestionHandlerOptions = {},
) => {
  let statusRequestCount = 0;
  let inFlightStatusRequests = 0;

  return [
    http.post(API, async ({ request }) => {
      const formData = await request.formData();
      if (uploadDelayMs) await delay(uploadDelayMs);
      if (!(formData.get("file") instanceof File)) {
        return HttpResponse.json(
          { error: "A file is required." },
          { status: 400 },
        );
      }

      if (uploadRejection) {
        return HttpResponse.json(
          { error: uploadRejection.message },
          { status: uploadRejection.status },
        );
      }

      return HttpResponse.json(ingestionResponse(fixture, "pending"), {
        status: 202,
      });
    }),
    http.get(`${API}/:id`, async ({ params }) => {
      if (params.id !== fixture.id) {
        return HttpResponse.json({ error: "Not found." }, { status: 404 });
      }

      statusRequestCount += 1;
      inFlightStatusRequests += 1;
      onStatusRequest?.(inFlightStatusRequests);
      if (statusDelayMs) await delay(statusDelayMs);
      inFlightStatusRequests -= 1;
      onStatusRequest?.(inFlightStatusRequests);
      if (statusRequestCount === statusErrorAt) {
        return HttpResponse.json(
          { error: "Unable to retrieve the import status. Please try again." },
          { status: 503 },
        );
      }

      const status =
        statusSequence?.[statusRequestCount - 1] ??
        (statusRequestCount === 1 ? "processing" : "completed");
      return HttpResponse.json(ingestionResponse(fixture, status));
    }),
  ];
};
