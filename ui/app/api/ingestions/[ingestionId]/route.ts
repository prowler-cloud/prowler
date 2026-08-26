import { NextResponse } from "next/server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { parseIngestion } from "@/lib/ingestions";
import { isCloud } from "@/lib/shared/env";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

interface IngestionRouteContext {
  params: Promise<{
    ingestionId: string;
  }>;
}

const INVALID_INGESTION_RESPONSE =
  "Unable to retrieve the import status. Please try again.";

export async function GET(
  _request: Request,
  { params }: IngestionRouteContext,
) {
  if (!isCloud()) return new Response(null, { status: 404 });

  const { ingestionId } = await params;
  if (!ingestionId) return new Response(null, { status: 404 });

  const headers = await getAuthHeaders({ contentType: false });
  const upstreamResponse = await fetch(
    `${apiBaseUrl}/ingestions/${encodeURIComponent(ingestionId)}`,
    { headers, cache: "no-store" },
  );
  const payload = await upstreamResponse.json().catch(() => undefined);

  if (!upstreamResponse.ok) {
    return NextResponse.json(
      { error: INVALID_INGESTION_RESPONSE },
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

  return NextResponse.json({ data: ingestion });
}
