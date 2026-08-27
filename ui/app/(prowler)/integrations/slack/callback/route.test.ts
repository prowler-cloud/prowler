/**
 * Unit tests for the Slack OAuth callback Route Handler. MSW (node) serves the
 * same contract double the browser tests use, so the real
 * `exchangeSlackOAuthCode` runs underneath — only Next's request-scoped pieces
 * (session, cache) are stubbed.
 */
import { setupServer } from "msw/node";
import { revalidatePath } from "next/cache";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { handlersForSlack } from "@/__tests__/msw/handlers/slack";
import {
  SLACK_EXCHANGE_OUTCOME,
  SLACK_OAUTH_CODE,
  SLACK_OAUTH_STATE,
  SLACK_RETRY_AFTER_SECONDS,
  SLACK_WORKSPACE_CONFLICT_CODE,
  slackFixture,
} from "@/__tests__/msw/handlers/slack.fixtures";
import type { SlackFixture } from "@/__tests__/msw/handlers/slack.fixtures";

import { GET, HEAD } from "./route";

// The MSW handlers read the literal `process.env.UI_API_BASE_URL`, which
// Vite's `define` inlines at build time; the action resolves the same var
// through `readEnv`'s computed access at module import, which `define` cannot
// reach. This hoisted block runs before either import so both agree.
vi.hoisted(() => {
  process.env.UI_API_BASE_URL ??= "http://localhost/api/v1";
});

vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
  revalidateTag: vi.fn(),
  unstable_cache: <T>(fn: T) => fn,
}));

// `auth()` reaches for a request scope the test has none of; the exchange only
// needs a bearer the double never checks.
vi.mock("@/auth.config", () => ({
  auth: vi.fn(() => Promise.resolve({ accessToken: "test-access-token" })),
}));

const server = setupServer();

const exchangeCalls: string[] = [];
server.events.on("request:start", ({ request }) => {
  if (
    request.method === "POST" &&
    request.url.includes("/slack/oauth/exchange")
  ) {
    exchangeCalls.push(request.url);
  }
});

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const CALLBACK_URL = "https://cloud.prowler.com/integrations/slack/callback";

const wire = (fixture: SlackFixture) =>
  server.use(...handlersForSlack(fixture));

const get = (query: string, headers?: HeadersInit) =>
  GET(new Request(`${CALLBACK_URL}?${query}`, { headers }));

const HAPPY_QUERY = `code=${SLACK_OAUTH_CODE}&state=${SLACK_OAUTH_STATE}`;

/** The redirect's target, with the `303` asserted on the way. */
const locationOf = (response: Response): URL => {
  expect(response.status).toBe(303);
  const location = response.headers.get("location");
  expect(location).not.toBeNull();
  return new URL(location as string);
};

const revalidatedPaths = () =>
  vi.mocked(revalidatePath).mock.calls.map(([path]) => path);

beforeEach(() => {
  vi.stubEnv("UI_CLOUD_ENABLED", "true");
  vi.mocked(revalidatePath).mockClear();
  exchangeCalls.length = 0;
});

describe("the Slack OAuth callback route", () => {
  it("exchanges the code and redirects to the integration page, leaking neither code nor state", async () => {
    wire(slackFixture());

    const location = locationOf(await get(HAPPY_QUERY));

    expect(location.pathname).toBe("/integrations/slack");
    expect(Array.from(location.searchParams.entries())).toEqual([
      ["slack", "connected"],
    ]);
    // The code is single-use: one exchange, no retry.
    expect(exchangeCalls).toHaveLength(1);
    // A completed install invalidates the cached "none connected".
    expect(revalidatedPaths()).toEqual(
      expect.arrayContaining(["/integrations", "/integrations/slack"]),
    );
  });

  it.each([
    SLACK_EXCHANGE_OUTCOME.UNREADABLE_NO_CONTENT,
    SLACK_EXCHANGE_OUTCOME.UNREADABLE_HTML,
    SLACK_EXCHANGE_OUTCOME.UNREADABLE_NO_DATA,
  ])(
    "reports an unreadable 2xx (%s) as unconfirmed, not as failed",
    async (exchangeOutcome) => {
      wire(slackFixture({ exchangeOutcome }));

      const location = locationOf(await get(HAPPY_QUERY));

      expect(Array.from(location.searchParams.entries())).toEqual([
        ["slack", "unconfirmed"],
      ]);
      // Nothing of the unreadable body rides the redirect.
      expect(location.href).not.toMatch(/DOCTYPE|html/i);
      // The 2xx says the install happened, so the cache goes with it.
      expect(revalidatedPaths()).toEqual(
        expect.arrayContaining(["/integrations", "/integrations/slack"]),
      );
    },
  );

  it("passes Slack's own refusal through as a token, exchanging nothing", async () => {
    const location = locationOf(await get("error=access_denied"));

    expect(Array.from(location.searchParams.entries())).toEqual([
      ["slack", "slack_error"],
      ["slack_reason", "access_denied"],
    ]);
    expect(exchangeCalls).toHaveLength(0);
  });

  it("lets the error win when Slack sends it alongside a code, so the code is not spent", async () => {
    const location = locationOf(
      await get(`error=access_denied&${HAPPY_QUERY}`),
    );

    expect(location.searchParams.get("slack")).toBe("slack_error");
    expect(exchangeCalls).toHaveLength(0);
  });

  it("drops a refusal reason that is not shaped like a token", async () => {
    for (const error of [
      "<script>alert(1)</script>",
      "Some long sentence, not a reason code.",
    ]) {
      const location = locationOf(
        await get(`error=${encodeURIComponent(error)}`),
      );

      expect(Array.from(location.searchParams.entries())).toEqual([
        ["slack", "slack_error"],
      ]);
      expect(location.href).not.toMatch(/script|alert|sentence/i);
    }
  });

  // The back button's path: replaying the callback re-sends a state/code the
  // API already consumed, which it refuses with a code-less 400.
  it.each([
    SLACK_EXCHANGE_OUTCOME.REFUSED_STATE,
    SLACK_EXCHANGE_OUTCOME.SLACK_REFUSED,
  ])(
    "reports a consumed or timed-out completion (%s) as expired, not as retryable",
    async (exchangeOutcome) => {
      wire(slackFixture({ exchangeOutcome }));

      const location = locationOf(await get(HAPPY_QUERY));

      expect(Array.from(location.searchParams.entries())).toEqual([
        ["slack", "expired"],
      ]);
    },
  );

  it("names the workspace conflict so the page can keep Prowler's wording for it", async () => {
    wire(
      slackFixture({
        exchangeOutcome: SLACK_EXCHANGE_OUTCOME.DIFFERENT_WORKSPACE,
      }),
    );

    const location = locationOf(await get(HAPPY_QUERY));

    expect(Array.from(location.searchParams.entries())).toEqual([
      ["slack", "error"],
      ["slack_code", SLACK_WORKSPACE_CONFLICT_CODE],
    ]);
  });

  it("carries the rate limit's wait so the page can say when to come back", async () => {
    wire(slackFixture({ rateLimited: true }));

    const location = locationOf(await get(HAPPY_QUERY));

    expect(Array.from(location.searchParams.entries())).toEqual([
      ["slack", "rate_limited"],
      ["slack_retry", String(SLACK_RETRY_AFTER_SECONDS)],
    ]);
  });

  it("reports Slack being broken upstream as an error", async () => {
    wire(slackFixture({ oauthUpstreamError: true }));

    const location = locationOf(await get(HAPPY_QUERY));

    expect(location.searchParams.get("slack")).toBe("error");
  });

  it.each([
    ["state", `code=${SLACK_OAUTH_CODE}`],
    ["code", `state=${SLACK_OAUTH_STATE}`],
  ])(
    "asks for nothing when the completion carries no %s",
    async (_missing, query) => {
      const location = locationOf(await get(query));

      expect(Array.from(location.searchParams.entries())).toEqual([
        ["slack", "incomplete"],
      ]);
      expect(exchangeCalls).toHaveLength(0);
    },
  );

  it("answers HEAD itself, since Next would otherwise run the GET for it", () => {
    const response = HEAD();

    expect(response.status).toBe(204);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(exchangeCalls).toHaveLength(0);
  });

  it("answers a prefetch nothing, so no intermediary burns the code", async () => {
    const prefetchHeaders: HeadersInit[] = [
      { "sec-purpose": "prefetch" },
      { purpose: "prefetch" },
      { "x-moz": "prefetch" },
    ];
    for (const headers of prefetchHeaders) {
      const response = await get(HAPPY_QUERY, headers);

      expect(response.status).toBe(204);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    }
    expect(exchangeCalls).toHaveLength(0);
  });

  it("detects a prefetch when an earlier purpose header describes navigation", async () => {
    // Given - different clients supplied purpose headers with mixed values.
    const headers = {
      "sec-purpose": "navigate",
      purpose: "prefetch",
      "x-moz": "navigate",
    };

    // When
    const response = await get(HAPPY_QUERY, headers);

    // Then - any prefetch marker prevents the single-use code exchange.
    expect(response.status).toBe(204);
    expect(exchangeCalls).toHaveLength(0);
  });

  it("exchanges the code when ordinary navigation follows a prefetch", async () => {
    // Given - a speculative request reached the callback before navigation.
    wire(slackFixture());
    const prefetchResponse = await get(HAPPY_QUERY, {
      "sec-purpose": "prefetch",
    });

    // When - the browser performs the ordinary callback navigation.
    const location = locationOf(await get(HAPPY_QUERY));

    // Then - the guard cannot be cached and the real exchange still runs once.
    expect(prefetchResponse.headers.get("Cache-Control")).toBe("no-store");
    expect(location.searchParams.get("slack")).toBe("connected");
    expect(exchangeCalls).toHaveLength(1);
  });

  it("sends non-cloud deployments home without exchanging anything", async () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    const location = locationOf(await get(HAPPY_QUERY));

    expect(location.pathname).toBe("/");
    expect(exchangeCalls).toHaveLength(0);
  });
});
