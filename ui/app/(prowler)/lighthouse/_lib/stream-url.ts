// Same-origin path for the Lighthouse v2 SSE proxy route handler.
//
// The browser EventSource MUST hit our own origin (not the cross-origin API
// host) so it doesn't fail on CORS, and so the access token stays server-side
// (it is attached by the route handler, never placed in the browser URL).
export function buildLighthouseV2StreamUrl(sessionId: string): string {
  return `/api/lighthouse/v2/sessions/${encodeURIComponent(sessionId)}/event-stream`;
}
