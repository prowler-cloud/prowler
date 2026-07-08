import type { NextFetchEvent } from "next/server";
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  authHandlerSpy,
  authMock,
  fetchMaintenanceStatusMock,
  maintenanceResponseMock,
} = vi.hoisted(() => ({
  authHandlerSpy: vi.fn(),
  // Minimal stand-in for next-auth's `auth()` wrapper: it takes the route
  // handler and returns a function with the (req, ctx) signature `proxy()`
  // calls `authProxy` with. The real handler reads `req.auth`, which a
  // plain NextRequest doesn't have, so `user`/`sessionError` resolve to
  // `undefined` here — irrelevant to what this suite asserts (the MM gate
  // itself), it only needs to observe whether authProxy ran.
  authMock: vi.fn(
    (handler: (req: unknown) => unknown) => (req: unknown, _ctx: unknown) => {
      authHandlerSpy(req);
      return handler(req);
    },
  ),
  fetchMaintenanceStatusMock: vi.fn(),
  maintenanceResponseMock: vi.fn(),
}));

vi.mock("@/auth.config", () => ({
  auth: authMock,
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "http://api:8000/api/v1",
}));

vi.mock("@/lib/maintenance", () => ({
  fetchMaintenanceStatus: fetchMaintenanceStatusMock,
  maintenanceResponse: maintenanceResponseMock,
  MAINTENANCE_PATH: "/maintenance",
}));

import proxy from "./proxy";

const makeRequest = (path: string) =>
  new NextRequest(new URL(`https://app.prowler.com${path}`));

describe("proxy() Maintenance Mode gate (isCloud gating)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('runs the maintenance status check when NEXT_PUBLIC_IS_CLOUD_ENV is "true"', async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    fetchMaintenanceStatusMock.mockResolvedValueOnce({
      enabled: false,
      message: null,
      started_at: null,
    });
    maintenanceResponseMock.mockReturnValueOnce(null);

    // When
    const response = await proxy(
      makeRequest("/scans") as any,
      {} as NextFetchEvent,
    );

    // Then: the gate ran (and, since it returned null here, fell through to
    // the auth-wrapped handler, which redirects unauthenticated visitors).
    expect(fetchMaintenanceStatusMock).toHaveBeenCalledTimes(1);
    expect(maintenanceResponseMock).toHaveBeenCalledTimes(1);
    expect(authHandlerSpy).toHaveBeenCalledTimes(1);
    expect(response.status).toBe(307);
  });

  it('is a no-op in self-hosted (NEXT_PUBLIC_IS_CLOUD_ENV is not "true"): the status fetch is never made and the request falls straight through to auth', async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    // When
    const response = await proxy(
      makeRequest("/scans") as any,
      {} as NextFetchEvent,
    );

    // Then
    expect(fetchMaintenanceStatusMock).not.toHaveBeenCalled();
    expect(maintenanceResponseMock).not.toHaveBeenCalled();
    expect(authHandlerSpy).toHaveBeenCalledTimes(1);
    expect(response.status).toBe(307);
  });

  it("is also a no-op when NEXT_PUBLIC_IS_CLOUD_ENV is unset", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", undefined);

    // When
    await proxy(makeRequest("/scans") as any, {} as NextFetchEvent);

    // Then
    expect(fetchMaintenanceStatusMock).not.toHaveBeenCalled();
    expect(maintenanceResponseMock).not.toHaveBeenCalled();
  });
});
