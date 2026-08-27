import type { NextAuthRequest } from "next-auth";
import { describe, expect, it, vi } from "vitest";

const { authWrapper } = vi.hoisted(() => ({
  authWrapper: vi.fn((handler: unknown) => handler),
}));

vi.mock("@/auth.config", () => ({ auth: authWrapper }));
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

const invokeProxy = (auth: NextAuthRequest["auth"]): Response => {
  const url = new URL(CALLBACK_URL);
  const request = {
    auth,
    nextUrl: url,
    url: url.toString(),
  } as NextAuthRequest;

  return (proxy as unknown as (request: NextAuthRequest) => Response)(request);
};

describe("Slack OAuth callback authentication", () => {
  it.each([
    {
      label: "the session expired",
      auth: { error: "RefreshAccessTokenError" } as NextAuthRequest["auth"],
    },
    { label: "the session is missing", auth: null },
  ])("strips the OAuth credentials before sign-in when $label", ({ auth }) => {
    // Given - Slack returned a single-use code to an unauthenticated callback.

    // When
    const response = invokeProxy(auth);

    // Then - sign-in resumes on a clean integration URL that asks for a new install.
    const location = new URL(response.headers.get("location") as string);
    expect(location.pathname).toBe("/sign-in");
    expect(location.searchParams.get("callbackUrl")).toBe(
      "/integrations/slack?slack=expired",
    );
    expect(location.href).not.toContain("slack-code-1f4a");
    expect(location.href).not.toContain("st-2f1c9d7a");
  });
});
