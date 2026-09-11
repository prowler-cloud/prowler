import { describe, expect, it, vi } from "vitest";

const { evaluateAccessMock } = vi.hoisted(() => ({
  evaluateAccessMock: vi.fn(),
}));
vi.mock("@/auth.config", () => ({ auth: (handler: unknown) => handler }));
vi.mock("@/lib/csp", () => ({ getCspHeader: () => "default-src 'self'" }));
vi.mock("@/lib/integrations", () => ({
  GATED_INTEGRATIONS: { posthog: "posthog" },
  isGatedIntegrationEnabled: () => false,
  readGatedEnv: () => null,
}));
vi.mock("@/lib/registry/access.server", () => ({
  evaluateRegistryAccess: evaluateAccessMock,
}));
vi.mock("@/lib/runtime-env", () => ({ readEnv: () => null }));
vi.mock("@/lib/shared/env", () => ({ isCloud: () => true }));
vi.mock("@/lib/utm", () => ({ copyAttributionParams: vi.fn() }));

import proxy from "./proxy";

const request = {
  auth: { accessToken: "current-token", user: {} },
  nextUrl: new URL("http://localhost/registry"),
  url: "http://localhost/registry",
};

describe("proxy", () => {
  it("redirects denied direct Registry requests to profile", async () => {
    // Given / When
    evaluateAccessMock.mockResolvedValue({ status: "ineligible" });
    const response = (await proxy(request as never, {} as never)) as Response;

    // Then
    expect(evaluateAccessMock).toHaveBeenCalledWith("current-token");
    expect(response.headers.get("location")).toBe("http://localhost/profile");
  });
});
