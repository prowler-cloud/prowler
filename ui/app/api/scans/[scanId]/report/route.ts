import { NextResponse } from "next/server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

interface ScanReportRouteContext {
  params: Promise<{
    scanId: string;
  }>;
}

const COPY_RESPONSE_HEADERS = [
  "content-length",
  "content-type",
  "etag",
  "last-modified",
] as const;

const PREFLIGHT_TIMEOUT_MS = 10_000;
const REPORT_PREPARATION_ERROR =
  "Unable to prepare the scan report. Please try again in a few minutes.";

const buildAttachmentFilename = (scanId: string) =>
  `scan-${scanId.replace(/[^a-zA-Z0-9._-]/g, "-")}-report.zip`;

const buildDownloadHeaders = (upstreamHeaders: Headers, scanId: string) => {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Disposition": `attachment; filename="${buildAttachmentFilename(scanId)}"`,
  });

  COPY_RESPONSE_HEADERS.forEach((headerName) => {
    const value = upstreamHeaders.get(headerName);
    if (value) headers.set(headerName, value);
  });

  if (!headers.has("content-type")) {
    headers.set("content-type", "application/zip");
  }

  return headers;
};

const isAbortError = (error: unknown) =>
  error instanceof DOMException &&
  (error.name === "AbortError" || error.name === "TimeoutError");

const isHtmlResponse = (headers: Headers) =>
  headers.get("content-type")?.toLowerCase().includes("text/html") ?? false;

const isRedirect = (status: number) => status >= 300 && status < 400;

const preflightReadyResponse = () =>
  new Response(null, {
    status: 204,
    headers: { "Cache-Control": "no-store" },
  });

export async function GET(
  request: Request,
  { params }: ScanReportRouteContext,
) {
  const { scanId } = await params;
  const headers = await getAuthHeaders({ contentType: false });
  const upstreamUrl = `${apiBaseUrl}/scans/${encodeURIComponent(scanId)}/report`;
  const isPreflight =
    new URL(request.url).searchParams.get("preflight") === "1";

  let upstreamResponse: Response;

  try {
    upstreamResponse = await fetch(upstreamUrl, {
      headers,
      cache: "no-store",
      // The API redirects S3-backed reports to a presigned URL; keep that
      // redirect instead of following it so the bytes never stream through
      // this server.
      redirect: "manual",
      signal: isPreflight
        ? AbortSignal.timeout(PREFLIGHT_TIMEOUT_MS)
        : undefined,
    });
  } catch (error) {
    if (isPreflight && isAbortError(error)) {
      return preflightReadyResponse();
    }

    throw error;
  }

  if (upstreamResponse.status === 202) {
    const body = await upstreamResponse.json().catch(() => ({}));
    return NextResponse.json(body, {
      status: 202,
      headers: { "Cache-Control": "no-store" },
    });
  }

  // S3-backed reports: hand the API's presigned redirect to the browser so it
  // downloads straight from S3 without proxying the bytes through this server.
  if (isRedirect(upstreamResponse.status)) {
    if (isPreflight) {
      return preflightReadyResponse();
    }

    const location = upstreamResponse.headers.get("location");
    if (!location) {
      return NextResponse.json(
        { error: "Report redirect did not include a location." },
        { status: 502, headers: { "Cache-Control": "no-store" } },
      );
    }

    return new Response(null, {
      status: 307,
      headers: { Location: location, "Cache-Control": "no-store" },
    });
  }

  if (!upstreamResponse.ok) {
    const body =
      isPreflight && isHtmlResponse(upstreamResponse.headers)
        ? REPORT_PREPARATION_ERROR
        : await upstreamResponse.text().catch(() => "");

    return new Response(body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type":
          isPreflight && isHtmlResponse(upstreamResponse.headers)
            ? "text/plain"
            : upstreamResponse.headers.get("content-type") || "text/plain",
      },
    });
  }

  // Self-hosted without S3: the API returns the bytes directly, so there is no
  // presigned URL to redirect to and we stream the response through instead.
  if (isPreflight) {
    await upstreamResponse.body?.cancel();
    return preflightReadyResponse();
  }

  if (!upstreamResponse.body) {
    return NextResponse.json(
      { error: "Report response did not include a readable body." },
      { status: 502, headers: { "Cache-Control": "no-store" } },
    );
  }

  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: buildDownloadHeaders(upstreamResponse.headers, scanId),
  });
}
