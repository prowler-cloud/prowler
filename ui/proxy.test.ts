import type { NextAuthRequest } from "next-auth";
import { describe, expect, it, vi } from "vitest";

vi.mock("next-auth", () => ({
  default: vi.fn(() => ({
    signIn: vi.fn(),
    signOut: vi.fn(),
    auth: vi.fn(),
    handlers: {},
  })),
}));

vi.mock("next-auth/providers/credentials", () => ({
  default: vi.fn((config) => config),
}));

vi.mock("@/auth.config", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/auth.config")>();

  return {
    ...actual,
    auth: vi.fn(
      (handler: (request: NextAuthRequest) => Response | Promise<Response>) =>
        async (request: NextAuthRequest) => {
          // Match NextAuth's production order: `authorized` can return a
          // response before the wrapped proxy handler is invoked.
          const authorization = await actual.authConfig.callbacks?.authorized?.(
            {
              auth: request.auth,
              request,
            },
          );

          if (authorization instanceof Response) return authorization;

          return handler(request);
        },
    ),
  };
});
vi.mock("@/lib/csp", () => ({ getCspHeader: () => "default-src 'self'" }));
vi.mock("@/lib/integrations", () => ({
  GATED_INTEGRATIONS: { posthog: "posthog" },
  isGatedIntegrationEnabled: () => false,
  readGatedEnv: () => undefined,
}));
vi.mock("@/lib/runtime-env", () => ({ readEnv: () => undefined }));
vi.mock("@/lib/shared/env", () => ({ isCloud: () => true }));

import proxy from "./proxy";

const CALLBACK_URL =
  "https://cloud.prowler.com/integrations/slack/callback" +
  "?code=slack-code-1f4a&state=st-2f1c9d7a";

const invokeProxy = async (
  auth: NextAuthRequest["auth"],
): Promise<Response> => {
  const url = new URL(CALLBACK_URL);
  const request = {
    auth,
    nextUrl: url,
    url: url.toString(),
  } as NextAuthRequest;

  return (proxy as unknown as (request: NextAuthRequest) => Promise<Response>)(
    request,
  );
};

describe("Slack OAuth callback authentication", () => {
  it.each([
    {
      label: "the session expired",
      auth: { error: "RefreshAccessTokenError" } as NextAuthRequest["auth"],
    },
    { label: "the session is missing", auth: null },
  ])(
    "strips the OAuth credentials before sign-in when $label",
    async ({ auth }) => {
      // Given - Slack returned a single-use code to an unauthenticated callback.

      // When
      const response = await invokeProxy(auth);

      // Then - sign-in resumes on a clean integration URL that asks for a new install.
      const location = new URL(response.headers.get("location") as string);
      expect(location.pathname).toBe("/sign-in");
      expect(location.searchParams.get("callbackUrl")).toBe(
        "/integrations/slack?slack=expired",
      );
      expect(location.href).not.toContain("slack-code-1f4a");
      expect(location.href).not.toContain("st-2f1c9d7a");
    },
  );
});
