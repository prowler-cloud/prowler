/**
 * What the Slack actions do off the DOM, which
 * `slack-page.integration.test.tsx` therefore cannot cover: which failures they
 * report to Sentry, and the URLs the channel listing's cursor pagination
 * follows.
 */

import { revalidatePath } from "next/cache";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  SLACK_GENERIC_ERROR_MESSAGE,
  SLACK_UNREADABLE_RESULT_MESSAGE,
} from "@/lib/integrations/slack-errors";
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

import {
  exchangeSlackOAuthCode,
  getSlackAuthorizeUrl,
  getSlackChannels,
  sendSlackTestMessage,
  setSlackDefaultChannel,
} from "./slack";

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

/**
 * The callback names the workspace and redirects on `integration` alone, so a
 * `2xx` body it cannot read back as an integration must not reach it.
 */
describe("exchangeSlackOAuthCode result shape", () => {
  const INTEGRATION = {
    id: "9b1f4c22-5e7a-4c2e-8f0d-6a3b1c9d7e42",
    type: "integrations",
    attributes: {
      integration_type: "slack",
      configuration: { team_name: "Prowler HQ" },
    },
  };

  const exchangeResponse = (data: unknown) =>
    new Response(JSON.stringify({ data }), {
      status: 200,
      headers: { "content-type": "application/vnd.api+json" },
    });

  it.each<[string, unknown]>([
    ["an empty object", {}],
    ["an array", []],
    ["a bare string", "invalid"],
    ["a resource with no id", { type: "integrations", attributes: {} }],
    ["a resource with an empty id", { ...INTEGRATION, id: "" }],
    ["a resource of another type", { ...INTEGRATION, type: "tasks" }],
    [
      "a resource with no attributes",
      { id: INTEGRATION.id, type: "integrations" },
    ],
    [
      "another kind of integration",
      {
        ...INTEGRATION,
        attributes: { ...INTEGRATION.attributes, integration_type: "jira" },
      },
    ],
  ])("cannot confirm the install from %s", async (_label, data) => {
    // Given — a 2xx whose `data` is truthy but is not an integration resource.
    fetchMock.mockResolvedValue(exchangeResponse(data));

    // When
    const result = await exchange();

    // Then — the answer for a body with no `data`: the install happened, only
    // its result is unknown.
    expect(result).toEqual({
      unconfirmed: true,
      message: SLACK_UNREADABLE_RESULT_MESSAGE,
    });
  });

  it("hands over the workspace the API upserted", async () => {
    // Given
    fetchMock.mockResolvedValue(exchangeResponse(INTEGRATION));

    // When / Then
    expect(await exchange()).toEqual({ integration: INTEGRATION });
  });
});

/** The shape the API's integration ids have, which is the only shape accepted. */
const SLACK_INTEGRATION_ID = "b2c7fd0a-3e51-4d8f-9a6c-1f0e2d3c4b5a";

/** The listing every cursor page of the channel read hangs off. */
const CHANNELS_URL =
  `https://api.test/api/v1/integrations/${SLACK_INTEGRATION_ID}` +
  "/slack/channels";

const FIRST_CHANNEL = { id: "C0123AB", name: "security" };
const SECOND_CHANNEL = { id: "C0789EF", name: "platform" };

/** A cursor page carrying one channel and whatever `links.next` is passed. */
const channelPage = (
  channel: { id: string; name: string },
  next: string | null,
) =>
  new Response(
    JSON.stringify({
      data: [
        {
          type: "slack-channels",
          id: channel.id,
          attributes: { name: channel.name, is_private: false },
        },
      ],
      links: { next },
    }),
    { status: 200, headers: { "content-type": "application/vnd.api+json" } },
  );

const channelOption = (channel: { id: string; name: string }) => ({
  id: channel.id,
  name: channel.name,
  is_private: false,
});

const requestedUrls = (): string[] =>
  fetchMock.mock.calls.map(([url]) => String(url));

describe("getSlackChannels", () => {
  it("follows a cursor-only `next` on the listing's own URL, not on the API root", async () => {
    // The link is opaque (design D6), so the API may answer with nothing but
    // the cursor. Resolved against the API root that link loses the
    // `/integrations/{id}/slack/channels` path, and every page after the first
    // disappears without anything saying so.
    fetchMock
      .mockResolvedValueOnce(channelPage(FIRST_CHANNEL, "?page[cursor]=2"))
      .mockResolvedValueOnce(channelPage(SECOND_CHANNEL, null));

    const result = await getSlackChannels(SLACK_INTEGRATION_ID);

    expect(requestedUrls()).toEqual([
      CHANNELS_URL,
      `${CHANNELS_URL}?page[cursor]=2`,
    ]);
    expect(result).toEqual({
      channels: [channelOption(FIRST_CHANNEL), channelOption(SECOND_CHANNEL)],
    });
  });

  it.each([
    {
      shape: "an absolute",
      next: "https://evil.test/api/v1/integrations/x/slack/channels?cursor=2",
    },
    { shape: "a protocol-relative", next: "//evil.test/api/v1/channels?c=2" },
  ])(
    "stops at $shape off-origin `next` rather than sending the tenant's token to it",
    async ({ next }) => {
      // Every page is fetched with the tenant's `Authorization` header. Node's
      // `fetch` strips it when a *redirect* leaves the origin; a hop the UI
      // makes itself gets no such protection, so the origin is checked here.
      fetchMock.mockResolvedValueOnce(channelPage(FIRST_CHANNEL, next));

      const result = await getSlackChannels(SLACK_INTEGRATION_ID);

      expect(requestedUrls()).toEqual([CHANNELS_URL]);
      // Pagination ends, it does not fail: the channels already read are still
      // the picker's options.
      expect(result).toEqual({ channels: [channelOption(FIRST_CHANNEL)] });
    },
  );

  it("answers an unreadable page as no channels rather than parser prose", async () => {
    fetchMock.mockResolvedValueOnce(unreadableOk(HTML_INTERSTITIAL));

    const result = await getSlackChannels(SLACK_INTEGRATION_ID);

    expect(result).toEqual({ channels: [] });
    expectNoParserProse(result);
  });
});

/**
 * A `2xx` whose body is not the JSON:API document the contract promises — an
 * empty answer, or the HTML a proxy or WAF puts in front of one. Reading it
 * must not throw: the raw `SyntaxError` message survives `sanitizeErrorMessage`
 * (V8 truncates the HTML snippet to ten characters, so the `<!doctype html>`
 * branch never matches it) and would be shown to the user verbatim.
 */
const HTML_INTERSTITIAL =
  "<!DOCTYPE html><html><body><h1>Checking your browser</h1></body></html>";

const unreadableOk = (body: string) =>
  new Response(body, {
    status: 200,
    headers: { "content-type": body ? "text/html" : "application/json" },
  });

/** V8's parser wording, which no user should ever be shown. */
const PARSER_PROSE = /unexpected (token|end of json)|not valid json/i;

const expectNoParserProse = (result: unknown) => {
  const message = (result as { error?: string }).error ?? "";
  expect(message).not.toMatch(PARSER_PROSE);
};

const INTEGRATION_URL = `https://api.test/api/v1/integrations/${SLACK_INTEGRATION_ID}`;

const saveChannel = () =>
  setSlackDefaultChannel(SLACK_INTEGRATION_ID, FIRST_CHANNEL.id);

const expectIntegrationsRevalidated = () => {
  expect(vi.mocked(revalidatePath).mock.calls).toEqual([
    ["/integrations"],
    ["/integrations/slack"],
  ]);
};

describe("setSlackDefaultChannel", () => {
  it("returns the saved integration and revalidates the pages listing it", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: {
            type: "integrations",
            id: SLACK_INTEGRATION_ID,
            attributes: {
              integration_type: "slack",
              configuration: {
                channel_id: FIRST_CHANNEL.id,
                channel_name: FIRST_CHANNEL.name,
              },
            },
          },
        }),
        {
          status: 200,
          headers: { "content-type": "application/vnd.api+json" },
        },
      ),
    );

    const result = await saveChannel();

    expect(requestedUrls()).toEqual([INTEGRATION_URL]);
    expect(result).toMatchObject({
      integration: {
        attributes: { configuration: { channel_name: FIRST_CHANNEL.name } },
      },
    });
    expectIntegrationsRevalidated();
  });

  it.each([
    { shape: "empty", body: "" },
    { shape: "an HTML interstitial", body: HTML_INTERSTITIAL },
  ])(
    "answers a $shape `200` as an unread result, not as a failed save",
    async ({ body }) => {
      fetchMock.mockResolvedValueOnce(unreadableOk(body));

      const result = await saveChannel();

      expect(result).toEqual({ error: SLACK_UNREADABLE_RESULT_MESSAGE });
      expectNoParserProse(result);
      // The API recorded the channel before answering, so both pages have to be
      // refreshed even though its answer could not be read.
      expectIntegrationsRevalidated();
    },
  );

  // The caller reads `integration.attributes.configuration`, so a guard any
  // shallower than that lets the miss surface later as a generic "something
  // went wrong" from the manager's catch.
  it.each([
    { shape: "no `data`", body: {} },
    { shape: "a null `data`", body: { data: null } },
    { shape: "a `data` with no configuration", body: { data: {} } },
  ])(
    "answers a `200` carrying $shape as an unread result",
    async ({ body }) => {
      fetchMock.mockResolvedValueOnce(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "content-type": "application/vnd.api+json" },
        }),
      );

      const result = await saveChannel();

      expect(result).toEqual({ error: SLACK_UNREADABLE_RESULT_MESSAGE });
      expectNoParserProse(result);
      expectIntegrationsRevalidated();
    },
  );
});

describe("sendSlackTestMessage", () => {
  it("answers an unreadable `202` as no task started, not as parser prose", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(HTML_INTERSTITIAL, {
        status: 202,
        headers: { "content-type": "text/html" },
      }),
    );

    const result = await sendSlackTestMessage(SLACK_INTEGRATION_ID);

    expect(result).toEqual({ error: "Slack did not start the test message." });
    expectNoParserProse(result);
  });
});

/** The calls whose only failure path is one line of copy. */
const COPY_ONLY_ACTIONS = [
  {
    name: "getSlackChannels",
    call: (id: string) => getSlackChannels(id),
  },
  {
    name: "setSlackDefaultChannel",
    call: (id: string) => setSlackDefaultChannel(id, FIRST_CHANNEL.id),
  },
  {
    name: "sendSlackTestMessage",
    call: (id: string) => sendSlackTestMessage(id),
  },
];

const rateLimitedResponse = () =>
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
  );

/**
 * Answering in copy is not a reason to stay silent: a `5xx` on these calls is
 * the same fault the OAuth ones report, so it reaches Sentry the same way —
 * without changing a word of what the user is told.
 */
describe.each(COPY_ONLY_ACTIONS)("$name", ({ call }) => {
  it("reports an upstream Slack failure and still answers in the same words", async () => {
    fetchMock.mockResolvedValue(
      errorResponse(UPSTREAM_STATUS, UPSTREAM_DETAIL),
    );

    const result = await call(SLACK_INTEGRATION_ID);

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

    // The API's own `detail`, which is what this 502 already said before it was
    // reported: the throw is caught by the action and carries the same string.
    expect(result).toEqual({ error: UPSTREAM_DETAIL });
  });

  it.each([
    {
      status: 503,
      why: "Slack being unavailable, not a fault",
      response: () => errorResponse(503, "Slack is unavailable."),
      expected: "Slack is unavailable.",
    },
    {
      status: 429,
      why: "a wait, not a fault",
      response: rateLimitedResponse,
      expected:
        "Slack is rate limiting Prowler right now. Try again in about 30 seconds.",
    },
    {
      status: 400,
      why: "a refusal the API meant to give",
      response: () => errorResponse(400, "No default channel is set."),
      expected: "No default channel is set.",
    },
  ])("reports nothing for a $status: that is $why", async (refusal) => {
    fetchMock.mockResolvedValue(refusal.response());

    const result = await call(SLACK_INTEGRATION_ID);

    expect(captureExceptionMock).not.toHaveBeenCalled();
    expect(captureMessageMock).not.toHaveBeenCalled();
    expect(result).toEqual({ error: refusal.expected });
  });
});

/**
 * The integration id is interpolated into every one of these URLs, so an id
 * that is not one has to be refused before the request is built rather than
 * sent as a path of its own.
 */
describe.each(COPY_ONLY_ACTIONS)("$name", ({ call }) => {
  it.each(["../../users", "not-a-uuid", ""])(
    "asks the API nothing when the integration id is %o",
    async (id) => {
      const result = await call(id);

      expect(fetchMock).not.toHaveBeenCalled();
      // The same answer a malformed exchange argument gets: nothing about a
      // refused id is the user's to act on.
      expect(result).toEqual({ error: SLACK_GENERIC_ERROR_MESSAGE });
    },
  );
});
