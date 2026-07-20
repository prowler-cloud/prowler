import { NextRequest, NextResponse } from "next/server";

/**
 * Shape of the public, unauthenticated `GET /api/v1/maintenance`
 * response. Flat JSON (NOT JSON:API) by design — the endpoint must answer
 * even when the DB is down, so it reads only from Redis.
 */
export interface MaintenanceStatus {
  enabled: boolean;
  message: string | null;
  started_at: string | null;
}

export const MAINTENANCE_PATH = "/maintenance";

const MAINTENANCE_STATUS_PATH = "/maintenance";

/**
 * Short timeout so a slow/hung status endpoint never blocks every request on
 * the edge. On timeout we fail-open (treat MM as off).
 */
const STATUS_FETCH_TIMEOUT_MS = 2000;

/**
 * Edge cache window for the status probe. Keeps the per-request fetch cheap
 * while still recovering within ~15s of an operator toggling MM on/off.
 */
const STATUS_REVALIDATE_SECONDS = 15;

/**
 * Fetch the public maintenance status from the API.
 *
 * Fail-open contract: ANY error (network, timeout, non-200, malformed body)
 * resolves to `{ enabled: false }`. A status blip must never lock users out —
 * the API itself is the enforcement layer (it returns 503 when MM is really
 * on); the UI gate is purely cosmetic, so erring toward "off" is safe.
 */
export const fetchMaintenanceStatus = async (
  // `@/lib`'s `apiBaseUrl` resolves via `readEnv`, which returns `string |
  // null` (not `undefined`) when unset.
  apiBaseUrl: string | null | undefined,
): Promise<MaintenanceStatus> => {
  const fallback: MaintenanceStatus = {
    enabled: false,
    message: null,
    started_at: null,
  };

  if (!apiBaseUrl) {
    return fallback;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), STATUS_FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(`${apiBaseUrl}${MAINTENANCE_STATUS_PATH}`, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
      next: { revalidate: STATUS_REVALIDATE_SECONDS },
    });

    if (!response.ok) {
      return fallback;
    }

    const data = (await response.json()) as Partial<MaintenanceStatus>;

    return {
      enabled: data?.enabled === true,
      message: typeof data?.message === "string" ? data.message : null,
      started_at: typeof data?.started_at === "string" ? data.started_at : null,
    };
  } catch {
    // Network error or aborted-by-timeout → fail open.
    return fallback;
  } finally {
    clearTimeout(timeout);
  }
};

/**
 * Decide what the maintenance gate should do for a given request, given the
 * current status. Pure and side-effect free so it can be unit-tested without
 * the Next runtime:
 *
 * - MM on, not already on `/maintenance` → rewrite to `/maintenance`,
 *   forwarding the ops-set message/started_at as request headers so the page
 *   can render them (preserve the URL so the user lands back where they were
 *   on recovery).
 * - MM on, already on `/maintenance` → TERMINAL `NextResponse.next()`. Must
 *   be truthy (not null) so `proxy()` returns it directly instead of falling
 *   through into `authProxy`, which would redirect an unauthenticated
 *   visitor to `/sign-in` instead of letting the maintenance page render.
 * - MM off, currently on `/maintenance` → redirect to `/`.
 * - Otherwise → no-op (let the request continue / the next handler run).
 */
export const maintenanceResponse = (
  request: NextRequest,
  status: MaintenanceStatus,
): NextResponse | null => {
  const { pathname } = request.nextUrl;
  const onMaintenancePage = pathname.startsWith(MAINTENANCE_PATH);

  if (status.enabled) {
    if (onMaintenancePage) {
      return NextResponse.next();
    }

    const url = new URL(MAINTENANCE_PATH, request.url);
    const headers = new Headers(request.headers);
    headers.set("x-maintenance-message", status.message ?? "");
    headers.set("x-maintenance-started-at", status.started_at ?? "");
    return NextResponse.rewrite(url, { request: { headers } });
  }

  if (onMaintenancePage) {
    return NextResponse.redirect(new URL("/", request.url));
  }

  return null;
};
