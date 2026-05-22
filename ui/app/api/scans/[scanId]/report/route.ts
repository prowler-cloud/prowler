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

export async function GET(
  request: Request,
  { params }: ScanReportRouteContext,
) {
  const { scanId } = await params;
  const headers = await getAuthHeaders({ contentType: false });
  const upstreamUrl = `${apiBaseUrl}/scans/${encodeURIComponent(scanId)}/report`;
  const isPreflight =
    new URL(request.url).searchParams.get("preflight") === "1";

  const upstreamResponse = await fetch(upstreamUrl, {
    headers,
    cache: "no-store",
  });

  if (upstreamResponse.status === 202) {
    const body = await upstreamResponse.json().catch(() => ({}));
    return NextResponse.json(body, {
      status: 202,
      headers: { "Cache-Control": "no-store" },
    });
  }

  if (!upstreamResponse.ok) {
    const body = await upstreamResponse.text().catch(() => "");
    return new Response(body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type":
          upstreamResponse.headers.get("content-type") || "text/plain",
      },
    });
  }

  if (isPreflight) {
    await upstreamResponse.body?.cancel();
    return new Response(null, {
      status: 204,
      headers: { "Cache-Control": "no-store" },
    });
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
