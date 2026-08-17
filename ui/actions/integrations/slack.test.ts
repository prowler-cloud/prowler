/**
 * What the Slack OAuth actions do with a refusal they cannot classify
 * themselves.
 *
 * The outcomes a user sees — unavailable, rate limited, the copy for a refused
 * completion — are covered from the pages in `slack-page.integration.test.tsx`.
 * What cannot be seen from there is whether a failure was *reported*: a Sentry
 * capture leaves no mark on the DOM. That is what these tests are for, so they
 * mock `@sentry/nextjs` and keep `handleApiResponse` real — the report is the
 * behaviour under test, not a collaborator to stub out.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SentryErrorSource, SentryErrorType } from "@/sentry";

const { captureExceptionMock, captureMessageMock, fetchMock } = vi.hoisted(
  () => ({
    /**
     * Marks what it captured, as the real SDK does.
     *
     * `Sentry.captureException` sets a non-enumerable `__sentry_captured__` on
     * the exception (`checkOrSetAlreadyCaught`), which is precisely how
     * `handleApiError` knows the throw it caught was already reported. A mock
     * that skipped it would make "reported once" unobservable here — and would
     * quietly report twice while the test said nothing.
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

// `handleApiResponse` is deliberately real — its 5xx capture is what is under
// test — and it reads its copy from `lib/helper`, which reaches next-auth
// through `@/auth.config`. Stubbing the session is what lets the real wording
// (and the real HTML sanitizing) load in a jsdom test.
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

/** The status the contract reserves for "Slack upstream broke" (design D). */
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
    // Given — the status the contract reserves for `internal_error`,
    // `fatal_error`, `service_unavailable` and transport failures.
    fetchMock.mockResolvedValue(
      errorResponse(UPSTREAM_STATUS, UPSTREAM_DETAIL, "service_unavailable"),
    );

    // When
    const result = await action();

    // Then — the repo's own 5xx handling ran, so the failure reached Sentry
    // rather than being classified locally into an `{ error }` nobody hears
    // about. Exactly once: it reports and throws, and the action's catch sees a
    // marked error and does not report it again.
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

    // And the user is still told something: the throw lands in the action's
    // existing catch, so this is a result the page renders — not a rejection
    // that strands the callback on its spinner.
    expect(result).toEqual({ error: UPSTREAM_DETAIL });
  });

  it("answers a 5xx the API described in HTML in Prowler's own words", async () => {
    // Given — a gateway answering in place of the API, so there is no `detail`
    // and nothing here can name a Slack condition.
    fetchMock.mockResolvedValue(
      new Response("<html><body><h1>502 Bad Gateway</h1></body></html>", {
        status: UPSTREAM_STATUS,
        statusText: "Bad Gateway",
        headers: { "content-type": "text/html" },
      }),
    );

    // When
    const result = await action();

    // Then — the same wording the rest of the UI gives a 5xx, with none of the
    // gateway's markup in it, and still reported.
    expect(result).toEqual({ error: GENERIC_SERVER_ERROR_MESSAGE });
    expect(captureExceptionMock).toHaveBeenCalledTimes(1);
  });

  it.each([503, 404])(
    "reports nothing for a %s: that is the feature being dark, not a fault",
    async (status) => {
      // Given — no Slack app in this deployment (503 while `SLACK_CLIENT_*` is
      // unset, 404 where no Slack API is served at all).
      fetchMock.mockResolvedValue(
        errorResponse(status, "Slack integration is not configured."),
      );

      // When
      const result = await action();

      // Then — capturing this would report the deliberate ship-dark state from
      // every tenant on every page load.
      expect(result).toEqual({ unavailable: true });
      expect(captureExceptionMock).not.toHaveBeenCalled();
    },
  );

  it("reports nothing when Slack is rate limiting: it is a wait, not a fault", async () => {
    // Given
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

    // When
    const result = await action();

    // Then
    expect(result).toMatchObject({ rateLimited: true, retryAfterSeconds: 30 });
    expect(captureExceptionMock).not.toHaveBeenCalled();
  });
});
