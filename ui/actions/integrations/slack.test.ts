/**
 * What the Slack actions do off the DOM, which
 * `slack-page.integration.test.tsx` cannot cover: which failures reach Sentry,
 * and the URLs the channel listing's cursor pagination follows.
 */

import { revalidatePath } from "next/cache";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  SLACK_GENERIC_ERROR_MESSAGE,
  SLACK_PARTIAL_CHANNEL_LIST_MESSAGE,
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
  // The task poll leaves breadcrumbs on every read it makes.
  addBreadcrumb: vi.fn(),
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
  disconnectSlackIntegration,
  exchangeSlackOAuthCode,
  getSlackAuthorizeUrl,
  getSlackChannels,
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

const CHANNELS_URL =
  `https://api.test/api/v1/integrations/${SLACK_INTEGRATION_ID}` +
  "/slack/channels";

const FIRST_CHANNEL = { id: "C0123AB", name: "security" };
const SECOND_CHANNEL = { id: "C0789EF", name: "platform" };

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

const sentBody = (callIndex = 0): unknown =>
  JSON.parse(String(fetchMock.mock.calls[callIndex]?.[1]?.body));

/**
 * `MAX_CHANNEL_PAGES` in the action, which a `"use server"` module cannot
 * export: only async functions may leave one.
 */
const MAX_CHANNEL_PAGES = 20;

const channelOptions = (count: number) =>
  Array.from({ length: count }, () => channelOption(FIRST_CHANNEL));

/** What a `429` carrying `Retry-After: 30` is turned into. */
const RATE_LIMITED_MESSAGE =
  "Slack is rate limiting Prowler right now. Try again in about 30 seconds.";

/** A dead grant as the API reports it: reason in `code`, prose in `detail`. */
const TOKEN_EXPIRED_CODE = "token_expired";
const TOKEN_EXPIRED_DETAIL = "Slack refused the request: token_expired.";
const TOKEN_EXPIRED_MESSAGE =
  "Prowler's Slack credential has expired. Connect the workspace again to restore access.";

describe("getSlackChannels", () => {
  it("follows a cursor-only `next` on the listing's own URL, not on the API root", async () => {
    // The link is opaque (design D6), so the API may answer with the cursor
    // alone; resolved against the API root it loses the listing's own path.
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
      // `fetch` strips the tenant's `Authorization` on a redirect that leaves
      // the origin, but not on a hop the UI makes itself.
      fetchMock.mockResolvedValueOnce(channelPage(FIRST_CHANNEL, next));

      const result = await getSlackChannels(SLACK_INTEGRATION_ID);

      expect(requestedUrls()).toEqual([CHANNELS_URL]);
      expect(result).toEqual({
        channels: [channelOption(FIRST_CHANNEL)],
        incomplete: SLACK_PARTIAL_CHANNEL_LIST_MESSAGE,
      });
    },
  );

  it("answers an unreadable page as no channels rather than parser prose", async () => {
    fetchMock.mockResolvedValueOnce(unreadableOk(HTML_INTERSTITIAL));

    const result = await getSlackChannels(SLACK_INTEGRATION_ID);

    expect(result).toEqual({ channels: [] });
    expectNoParserProse(result);
  });

  it("says the list is short of the workspace when the page budget runs out", async () => {
    // The budget exists because `conversations.list` is tier 2 and a workspace
    // can outgrow it (design.md, Risks). A fresh `Response` per call: one
    // instance is already consumed on its second read.
    fetchMock.mockImplementation(() =>
      Promise.resolve(channelPage(FIRST_CHANNEL, "?page[cursor]=next")),
    );

    const result = await getSlackChannels(SLACK_INTEGRATION_ID);

    expect(fetchMock).toHaveBeenCalledTimes(MAX_CHANNEL_PAGES);
    expect(result).toEqual({
      channels: channelOptions(MAX_CHANNEL_PAGES),
      incomplete: SLACK_PARTIAL_CHANNEL_LIST_MESSAGE,
    });
  });

  it("says nothing about a short list for a workspace that just fits the budget", async () => {
    let page = 0;
    fetchMock.mockImplementation(() => {
      page += 1;
      return Promise.resolve(
        channelPage(
          FIRST_CHANNEL,
          page < MAX_CHANNEL_PAGES ? `?page[cursor]=${page}` : null,
        ),
      );
    });

    const result = await getSlackChannels(SLACK_INTEGRATION_ID);

    expect(fetchMock).toHaveBeenCalledTimes(MAX_CHANNEL_PAGES);
    expect(result).toEqual({ channels: channelOptions(MAX_CHANNEL_PAGES) });
    expect(result).not.toHaveProperty("incomplete");
  });

  it("keeps the pages it read when a later one is refused, saying why the list stops", async () => {
    fetchMock
      .mockResolvedValueOnce(channelPage(FIRST_CHANNEL, "?page[cursor]=2"))
      .mockResolvedValueOnce(rateLimitedResponse());

    const result = await getSlackChannels(SLACK_INTEGRATION_ID);

    // A rate limit says nothing about the grant, so the truncation names none.
    expect(result).toEqual({
      channels: [channelOption(FIRST_CHANNEL)],
      incomplete: RATE_LIMITED_MESSAGE,
      code: null,
    });
  });

  it("names the reason a later page was refused, not only the wording", async () => {
    fetchMock
      .mockResolvedValueOnce(channelPage(FIRST_CHANNEL, "?page[cursor]=2"))
      .mockResolvedValueOnce(
        errorResponse(400, TOKEN_EXPIRED_DETAIL, TOKEN_EXPIRED_CODE),
      );

    const result = await getSlackChannels(SLACK_INTEGRATION_ID);

    expect(result).toEqual({
      channels: [channelOption(FIRST_CHANNEL)],
      incomplete: TOKEN_EXPIRED_MESSAGE,
      code: TOKEN_EXPIRED_CODE,
    });
  });

  it("answers a refusal on the first page as a failure, having nothing to show", async () => {
    fetchMock.mockResolvedValueOnce(rateLimitedResponse());

    const result = await getSlackChannels(SLACK_INTEGRATION_ID);

    expect(result).toEqual({ error: RATE_LIMITED_MESSAGE, code: null });
  });
});

/**
 * A `2xx` whose body is not JSON:API: an empty answer, or the HTML a proxy or
 * WAF puts in front of one. The raw `SyntaxError` survives
 * `sanitizeErrorMessage` (V8 truncates the snippet to ten characters, so its
 * `<!doctype html>` branch never matches) and would be shown verbatim.
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

/** The save as the API answers it: the channel's name derived server-side. */
const savedIntegration = () =>
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
  );

const expectIntegrationsRevalidated = () => {
  expect(vi.mocked(revalidatePath).mock.calls).toEqual([
    ["/integrations"],
    ["/integrations/slack"],
  ]);
};

describe("setSlackDefaultChannel", () => {
  it("returns the saved integration and revalidates the pages listing it", async () => {
    fetchMock.mockResolvedValueOnce(savedIntegration());

    const result = await saveChannel();

    expect(requestedUrls()).toEqual([INTEGRATION_URL]);
    expect(result).toMatchObject({
      integration: {
        attributes: { configuration: { channel_name: FIRST_CHANNEL.name } },
      },
    });
    expectIntegrationsRevalidated();
  });

  // The write serializer names whatever it will not take and refuses the whole
  // save, so a body that also carried the integration's own (immutable) type
  // came back as `Invalid fields: {'integration_type'}` and recorded nothing.
  it("submits the channel as the save's only attribute", async () => {
    fetchMock.mockResolvedValueOnce(savedIntegration());

    await saveChannel();

    expect(sentBody()).toEqual({
      data: {
        type: "integrations",
        id: SLACK_INTEGRATION_ID,
        attributes: { configuration: { channel_id: FIRST_CHANNEL.id } },
      },
    });
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
      // The API recorded the channel before answering, so both pages refresh.
      expectIntegrationsRevalidated();
    },
  );

  // The caller reads `integration.attributes.configuration`, so a shallower
  // guard lets the miss surface later as the manager's generic catch.
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
    name: "disconnectSlackIntegration",
    call: (id: string) => disconnectSlackIntegration(id),
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
    // None of these refusals names a `code`.
    expect(result).toEqual({ error: refusal.expected, code: null });
  });
});

/**
 * The integration id is interpolated into every one of these URLs, so a
 * malformed one is refused before the request is built.
 */
describe.each(COPY_ONLY_ACTIONS)("$name", ({ call }) => {
  it.each(["../../users", "not-a-uuid", ""])(
    "asks the API nothing when the integration id is %o",
    async (id) => {
      const result = await call(id);

      expect(fetchMock).not.toHaveBeenCalled();
      expect(result).toEqual({ error: SLACK_GENERIC_ERROR_MESSAGE });
    },
  );
});
