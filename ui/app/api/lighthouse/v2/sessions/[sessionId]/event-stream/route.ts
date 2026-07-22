import { auth } from "@/auth.config";
import { apiBaseUrl } from "@/lib/helper";

// Always stream live; never cache or statically optimize this route.
export const dynamic = "force-dynamic";

/**
 * Reverse-proxy the Django Server-Sent Events stream for a Lighthouse v2
 * session so the browser EventSource talks to our own origin.
 *
 * Why this exists: an EventSource opened directly against the cross-origin API
 * host fails (CORS / unreachable internal host) and would expose the access
 * token in the browser URL. Here the request is made server-side with the
 * Authorization header, and the upstream SSE body is piped straight back.
 */
export async function GET(
  request: Request,
  { params }: { params: Promise<{ sessionId: string }> },
) {
  const { sessionId } = await params;

  const session = await auth();
  if (!session?.accessToken) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!apiBaseUrl) {
    return Response.json(
      { error: "API base URL is not configured." },
      { status: 500 },
    );
  }

  const upstreamUrl = `${apiBaseUrl}/lighthouse/sessions/${encodeURIComponent(
    sessionId,
  )}/event-stream`;

  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers: {
        Accept: "text/event-stream",
        Authorization: `Bearer ${session.accessToken}`,
      },
      cache: "no-store",
      // Abort the upstream connection when the browser closes the EventSource,
      // so we don't leak open SSE connections to the API.
      signal: request.signal,
    });
  } catch {
    return Response.json(
      { error: "Unable to reach the response stream." },
      { status: 502 },
    );
  }

  if (!upstream.ok || !upstream.body) {
    return Response.json(
      { error: "Unable to open the response stream." },
      { status: upstream.status || 502 },
    );
  }

  // Pipe the upstream SSE body straight through, disabling any buffering so
  // tokens flush to the client as they arrive.
  return new Response(upstream.body, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
