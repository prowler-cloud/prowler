// Local development fallback. Docker Compose injects PROWLER_API_HEALTH_URL
// with the internal service hostname (`api`) for container-to-container checks.
const DEFAULT_API_HEALTH_URL = "http://localhost:8080/health/ready";
const API_HEALTH_TIMEOUT_MS = 3000;

const createHealthResponse = (isApiHealthy: boolean) => ({
  status: isApiHealthy ? "healthy" : "unhealthy",
  service: "prowler-ui",
  dependencies: {
    api: isApiHealthy ? "healthy" : "unhealthy",
  },
});

const getApiHealthUrl = () =>
  process.env.PROWLER_API_HEALTH_URL?.trim() || DEFAULT_API_HEALTH_URL;

const isApiReady = async () => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), API_HEALTH_TIMEOUT_MS);

  try {
    const response = await fetch(getApiHealthUrl(), {
      cache: "no-store",
      signal: controller.signal,
    });

    return response.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
};

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  const isHealthy = await isApiReady();

  return Response.json(createHealthResponse(isHealthy), {
    status: isHealthy ? 200 : 503,
  });
}
