/**
 * Sentry reporting for the Slack OAuth actions. A capture leaves no mark on the
 * DOM, so it cannot be covered from `slack-page.integration.test.tsx`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SentryErrorSource, SentryErrorType } from "@/sentry";

const { captureExceptionMock, captureMessageMock, fetchMock } = vi.hoisted(
  () => ({
    /**
     * The real SDK marks the exception `__sentry_captured__`, and
     * `handleApiError` reads that mark to avoid reporting the same throw twice.
     */
    captureExceptionMock: vi.fn((exception: unknown, _options?: unknown) => {
      if (exception !== null && typeof exception === "object") {
        Object.defineProperty(exception, "__sentry_captured__", {
          configurable: true,
          value: true,
        });
      }
    }),
    captureMessageMock: vi.fn(),
    fetchMock: vi.fn(),
  }),
);

vi.mock("@sentry/nextjs", () => ({
  captureException: captureExceptionMock,
  captureMessage: captureMessageMock,
}));

vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
}));

// The real `handleApiResponse` reads its copy from `lib/helper`, which reaches
// next-auth through `@/auth.config`; stubbing the session lets that copy load.
vi.mock("@/auth.config", () => ({
  auth: vi.fn(() => Promise.resolve({ accessToken: "test-access-token" })),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: vi.fn(() =>
    Promise.resolve({ Authorization: "Bearer test-token" }),
  ),
  parseStringify: (value: unknown) => value,
}));

import { exchangeSlackOAuthCode, getSlackAuthorizeUrl } from "./slack";

/** The status the contract reserves for an upstream Slack failure. */
const UPSTREAM_STATUS = 502;
const UPSTREAM_DETAIL = "Slack is temporarily unavailable.";
const GENERIC_SERVER_ERROR_MESSAGE =
  "Server is temporarily unavailable. Please try again in a few minutes.";

const errorResponse = (status: number, detail: string, code?: string) =>
  new Response(
    JSON.stringify({
      errors: [
        {
          status: String(status),
          ...(code ? { code } : {}),
          detail,
          source: { pointer: "/data" },
        },
      ],
    }),
    { status, headers: { "content-type": "application/vnd.api+json" } },
  );

const exchange = () =>
  exchangeSlackOAuthCode({ code: "slack-code-1f4a", state: "st-2f1c9d7a" });

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe.each([
  { action: getSlackAuthorizeUrl, name: "getSlackAuthorizeUrl" },
  { action: exchange, name: "exchangeSlackOAuthCode" },
])("$name", ({ action }) => {
  it("reports an upstream Slack failure instead of only turning it into copy", async () => {
    // 502 covers `internal_error`, `fatal_error`, `service_unavailable` and
    // transport failures.
    fetchMock.mockResolvedValue(
      errorResponse(UPSTREAM_STATUS, UPSTREAM_DETAIL, "service_unavailable"),
    );

    const result = await action();

    // Once, not twice: `handleApiResponse` reports and throws, and the action's
    // catch sees the mark.
    expect(captureExceptionMock).toHaveBeenCalledTimes(1);
    expect(captureExceptionMock.mock.calls[0]?.[1]).toMatchObject({
      tags: {
        api_error: true,
        error_source: SentryErrorSource.HANDLE_API_RESPONSE,
        error_type: SentryErrorType.SERVER_ERROR,
        status_code: String(UPSTREAM_STATUS),
      },
    });
    expect(captureMessageMock).not.toHaveBeenCalled();

    // The throw lands in the action's catch, so the page gets a result to
    // render rather than a rejection that strands the callback on its spinner.
    expect(result).toEqual({ error: UPSTREAM_DETAIL });
  });

  it("answers a 5xx the API described in HTML in Prowler's own words", async () => {
    fetchMock.mockResolvedValue(
      new Response("<html><body><h1>502 Bad Gateway</h1></body></html>", {
        status: UPSTREAM_STATUS,
        statusText: "Bad Gateway",
        headers: { "content-type": "text/html" },
      }),
    );

    const result = await action();

    expect(result).toEqual({ error: GENERIC_SERVER_ERROR_MESSAGE });
    expect(captureExceptionMock).toHaveBeenCalledTimes(1);
  });

  it.each([503, 404])(
    "reports nothing for a %s: that is the feature being dark, not a fault",
    async (status) => {
      // 503 means `SLACK_CLIENT_*` is unset; 404 means no Slack API is served
      // in this deployment at all.
      fetchMock.mockResolvedValue(
        errorResponse(status, "Slack integration is not configured."),
      );

      const result = await action();

      // Capturing this would report the deliberate ship-dark state from every
      // tenant on every page load.
      expect(result).toEqual({ unavailable: true });
      expect(captureExceptionMock).not.toHaveBeenCalled();
    },
  );

  it("reports nothing when Slack is rate limiting: it is a wait, not a fault", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          errors: [{ status: "429", detail: "Slack is rate limiting." }],
        }),
        {
          status: 429,
          headers: {
            "content-type": "application/vnd.api+json",
            "Retry-After": "30",
          },
        },
      ),
    );

    const result = await action();

    expect(result).toMatchObject({ rateLimited: true, retryAfterSeconds: 30 });
    expect(captureExceptionMock).not.toHaveBeenCalled();
  });
});

/**
 * The URL is rendered as the `Add to Slack` link's `href`, so a value the API
 * got wrong must not become a redirect to somewhere that is not Slack.
 */
describe("getSlackAuthorizeUrl authorize URL", () => {
  const NO_AUTHORIZE_URL_MESSAGE = "Slack did not return an authorization URL.";
  const CONSENT_SCREEN_URL =
    "https://slack.com/oauth/v2/authorize" +
    "?client_id=1234567890.0987654321&state=st-2f1c9d7a";

  const authorizeUrlResponse = (authorizeUrl: unknown) =>
    new Response(JSON.stringify({ meta: { authorize_url: authorizeUrl } }), {
      status: 200,
      headers: { "content-type": "application/vnd.api+json" },
    });

  it.each([
    ["a hostile scheme", "javascript:alert(document.domain)"],
    ["plain HTTP", "http://slack.com/oauth/v2/authorize?client_id=1"],
    ["another origin", "https://evil.test/oauth/v2/authorize?client_id=1"],
    ["a lookalike hostname", "https://slack.com.evil.test/oauth/v2/authorize"],
    [
      "another Slack path",
      "https://slack.com/redirect?to=https%3A%2F%2Fevil.test",
    ],
    ["a value that is not a URL", "oauth/v2/authorize"],
  ])(
    "refuses %s instead of offering it as the install link",
    async (_label, authorizeUrl) => {
      // Given — a 2xx whose `meta.authorize_url` is not Slack's consent screen.
      fetchMock.mockResolvedValue(authorizeUrlResponse(authorizeUrl));

      // When
      const result = await getSlackAuthorizeUrl();

      // Then — the answer for no URL at all: nothing here is safe to link to.
      expect(result).toEqual({ error: NO_AUTHORIZE_URL_MESSAGE });
    },
  );

  it("hands over Slack's consent screen with its query untouched", async () => {
    // Given
    fetchMock.mockResolvedValue(authorizeUrlResponse(CONSENT_SCREEN_URL));

    // When / Then
    expect(await getSlackAuthorizeUrl()).toEqual({
      authorizeUrl: CONSENT_SCREEN_URL,
    });
  });
});
