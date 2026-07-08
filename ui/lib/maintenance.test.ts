import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  fetchMaintenanceStatus,
  maintenanceResponse,
  type MaintenanceStatus,
} from "./maintenance";

const API_BASE_URL = "https://api.example.com/api/v1";

const fetchMock = vi.fn();

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

const makeRequest = (path: string) =>
  new NextRequest(new URL(`https://app.prowler.com${path}`));

describe("fetchMaintenanceStatus", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("returns the parsed status when MM is enabled", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        enabled: true,
        message: "Scheduled DB maintenance.",
        started_at: "2026-06-17T10:00:00Z",
      }),
    );

    // When
    const status = await fetchMaintenanceStatus(API_BASE_URL);

    // Then
    expect(status).toEqual({
      enabled: true,
      message: "Scheduled DB maintenance.",
      started_at: "2026-06-17T10:00:00Z",
    });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${API_BASE_URL}/maintenance`);
    expect(init).toMatchObject({
      headers: { Accept: "application/json" },
      next: { revalidate: 15 },
    });
  });

  it("returns MM off when the endpoint reports disabled", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ enabled: false, message: null, started_at: null }),
    );

    // When
    const status = await fetchMaintenanceStatus(API_BASE_URL);

    // Then
    expect(status.enabled).toBe(false);
  });

  it("fails open when the API base URL is missing", async () => {
    // When
    const status = await fetchMaintenanceStatus(undefined);

    // Then
    expect(status).toEqual({
      enabled: false,
      message: null,
      started_at: null,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fails open on a non-200 response", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(jsonResponse({ enabled: true }, 500));

    // When
    const status = await fetchMaintenanceStatus(API_BASE_URL);

    // Then
    expect(status.enabled).toBe(false);
  });

  it("fails open on a network error / timeout", async () => {
    // Given
    fetchMock.mockRejectedValueOnce(new Error("network down"));

    // When
    const status = await fetchMaintenanceStatus(API_BASE_URL);

    // Then
    expect(status.enabled).toBe(false);
  });

  it("coerces a malformed body to MM off", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(jsonResponse({ unexpected: "shape" }));

    // When
    const status = await fetchMaintenanceStatus(API_BASE_URL);

    // Then
    expect(status).toEqual({
      enabled: false,
      message: null,
      started_at: null,
    });
  });
});

describe("maintenanceResponse", () => {
  const enabled: MaintenanceStatus = {
    enabled: true,
    message: "Down for maintenance.",
    started_at: "2026-06-17T10:00:00Z",
  };
  const disabled: MaintenanceStatus = {
    enabled: false,
    message: null,
    started_at: null,
  };

  it("rewrites to /maintenance when MM is enabled and not already there", () => {
    // When
    const response = maintenanceResponse(makeRequest("/scans"), enabled);

    // Then
    expect(response).not.toBeNull();
    expect(response?.headers.get("x-middleware-rewrite")).toBe(
      "https://app.prowler.com/maintenance",
    );
  });

  it("forwards the ops-set message and started_at as request headers on rewrite", () => {
    // When
    const response = maintenanceResponse(makeRequest("/scans"), enabled);

    // Then
    expect(response?.headers.get("x-middleware-override-headers")).toContain(
      "x-maintenance-message",
    );
    expect(
      response?.headers.get("x-middleware-request-x-maintenance-message"),
    ).toBe("Down for maintenance.");
    expect(
      response?.headers.get("x-middleware-request-x-maintenance-started-at"),
    ).toBe("2026-06-17T10:00:00Z");
  });

  it("forwards empty-string headers (not the literal string 'null') when message/started_at are null", () => {
    // Given
    const enabledNoMessage: MaintenanceStatus = {
      enabled: true,
      message: null,
      started_at: null,
    };

    // When
    const response = maintenanceResponse(
      makeRequest("/scans"),
      enabledNoMessage,
    );

    // Then
    expect(
      response?.headers.get("x-middleware-request-x-maintenance-message"),
    ).toBe("");
    expect(
      response?.headers.get("x-middleware-request-x-maintenance-started-at"),
    ).toBe("");
  });

  it("returns a terminal NextResponse.next() when MM is enabled and already on /maintenance (no auth fallthrough)", () => {
    // When
    const response = maintenanceResponse(makeRequest("/maintenance"), enabled);

    // Then: must be truthy so `proxy()` returns it directly instead of
    // falling through into `authProxy`, which would redirect an
    // unauthenticated visitor to /sign-in.
    expect(response).not.toBeNull();
    expect(response?.headers.get("x-middleware-next")).toBe("1");
    // And it must NOT be a redirect/rewrite — this is the actual page render.
    expect(response?.headers.get("location")).toBeNull();
    expect(response?.headers.get("x-middleware-rewrite")).toBeNull();
  });

  it("redirects /maintenance back to / when MM is disabled", () => {
    // When
    const response = maintenanceResponse(makeRequest("/maintenance"), disabled);

    // Then
    expect(response?.status).toBe(307);
    expect(response?.headers.get("location")).toBe("https://app.prowler.com/");
  });

  it("is a no-op (fail-open) when MM is disabled on a normal route", () => {
    // When
    const response = maintenanceResponse(makeRequest("/scans"), disabled);

    // Then
    expect(response).toBeNull();
  });
});

describe("proxy.ts matcher config", () => {
  it("no longer excludes /maintenance from the gate", async () => {
    // The gate must run on /maintenance too, otherwise its terminal branch
    // (MM on + already on /maintenance) never executes and the request falls
    // through to authProxy, which redirects unauthenticated visitors to
    // /sign-in instead of serving the maintenance page. Read the raw matcher
    // pattern to guard against a regression re-adding the exclusion.
    const path = await import("node:path");
    const fs = await import("node:fs/promises");
    const proxyModule = await fs.readFile(
      path.resolve(process.cwd(), "proxy.ts"),
      "utf-8",
    );
    const matcherLine = proxyModule
      .split("\n")
      .find((line) => line.includes("api|_next/static"));

    expect(matcherLine).toBeDefined();
    expect(matcherLine).not.toContain("maintenance|");
  });
});
