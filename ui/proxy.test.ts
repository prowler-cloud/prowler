import { NextRequest } from "next/server";
import type { NextAuthRequest } from "next-auth";
import { describe, expect, it, vi } from "vitest";

import proxy from "./proxy";

vi.mock("@/auth.config", () => ({
  auth: (handler: unknown) => handler,
}));

type ProxyHandler = (request: NextAuthRequest) => Response;

const handleProxyRequest = proxy as unknown as ProxyHandler;

const createAuthenticatedRequest = (url: string): NextAuthRequest =>
  Object.assign(new NextRequest(url), {
    auth: { user: {} },
  }) as NextAuthRequest;

describe("proxy", () => {
  it("should preserve Cloud attribution when an authenticated user opens sign-up", () => {
    // Given
    const request = createAuthenticatedRequest(
      "https://cloud.prowler.com/sign-up?utm_source=local-server&utm_content=alerts",
    );

    // When
    const response = handleProxyRequest(request);

    // Then
    expect(response.headers.get("location")).toBe(
      "https://cloud.prowler.com/?utm_source=local-server&utm_content=alerts",
    );
  });

  it("should keep only the supported attribution params on the dashboard", () => {
    // Given
    const request = createAuthenticatedRequest(
      "https://cloud.prowler.com/sign-in?utm_source=local-server&utm_content=lighthouse-ai&utm_campaign=upgrade&next=https%3A%2F%2Fexample.com",
    );

    // When
    const response = handleProxyRequest(request);

    // Then
    expect(response.headers.get("location")).toBe(
      "https://cloud.prowler.com/?utm_source=local-server&utm_content=lighthouse-ai",
    );
  });
});
