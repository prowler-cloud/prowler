import { NextResponse } from "next/server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { parseIngestion } from "@/lib/ingestions";
import { isCloud } from "@/lib/shared/env";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const INVALID_INGESTION_RESPONSE =
  "Unable to start the import. Please try again.";
const INGESTION_REJECTION_BY_CODE = {
  invalid: "The report is not a valid Prowler OCSF finding report.",
  subscription_required:
    "A Prowler Cloud subscription is required to import findings.",
  permission_denied: "You do not have permission to import findings.",
  file_too_large: "The selected file exceeds the allowed upload size.",
  rate_limited: "Too many import requests. Please try again shortly.",
} as const;

const INGESTION_REJECTION_BY_STATUS = {
  400: INGESTION_REJECTION_BY_CODE.invalid,
  402: INGESTION_REJECTION_BY_CODE.subscription_required,
  403: INGESTION_REJECTION_BY_CODE.permission_denied,
  413: INGESTION_REJECTION_BY_CODE.file_too_large,
  429: INGESTION_REJECTION_BY_CODE.rate_limited,
} as const;

const ingestionRejectionMessage = (
  payload: unknown,
  status: number,
  fallback: string,
): string => {
  if (typeof payload === "object" && payload !== null && "errors" in payload) {
    const errors = payload.errors;
    if (Array.isArray(errors) && typeof errors[0]?.code === "string") {
      const message =
        INGESTION_REJECTION_BY_CODE[
          errors[0].code as keyof typeof INGESTION_REJECTION_BY_CODE
        ];
      if (message) return message;
    }
  }

  return (
    INGESTION_REJECTION_BY_STATUS[
      status as keyof typeof INGESTION_REJECTION_BY_STATUS
    ] ?? fallback
  );
};

export async function POST(request: Request) {
  if (!isCloud()) return new Response(null, { status: 404 });

  const headers = await getAuthHeaders({ contentType: false });
  const contentType = request.headers.get("content-type");
  const contentLength = request.headers.get("content-length");

  if (contentType) headers["Content-Type"] = contentType;
  // Without the length the stream is forwarded chunked, and the ingestion API
  // parses no file out of a chunked multipart body: refuse rather than spend
  // the upload on a request that cannot succeed.
  if (!contentLength) {
    return NextResponse.json(
      { error: INVALID_INGESTION_RESPONSE },
      { status: 411 },
    );
  }
  headers["Content-Length"] = contentLength;

  const upstreamRequest: RequestInit & { duplex: "half" } = {
    method: "POST",
    headers,
    body: request.body,
    duplex: "half",
    cache: "no-store",
  };
  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetch(`${apiBaseUrl}/ingestions`, upstreamRequest);
  } catch {
    return NextResponse.json(
      { error: INVALID_INGESTION_RESPONSE },
      { status: 502 },
    );
  }
  const payload = await upstreamResponse.json().catch(() => undefined);

  if (!upstreamResponse.ok) {
    return NextResponse.json(
      {
        error: ingestionRejectionMessage(
          payload,
          upstreamResponse.status,
          INVALID_INGESTION_RESPONSE,
        ),
      },
      { status: upstreamResponse.status },
    );
  }

  const ingestion = parseIngestion(payload);
  if (!ingestion) {
    return NextResponse.json(
      { error: INVALID_INGESTION_RESPONSE },
      { status: 502 },
    );
  }

  return NextResponse.json(
    { data: ingestion },
    { status: upstreamResponse.status },
  );
}
