/**
 * Browser-mode tests for the Slack integration pages (`/integrations/slack`
 * and its OAuth callback).
 *
 * Tests are grouped by what the user is doing — starting the install, coming
 * back from Slack, living with a connected workspace — and reach the pages only
 * through `SlackIntegrationHarness`. The API is the cloud lane's, so MSW
 * answers from handlers derived from `design.md`'s contract: a scenario that
 * cannot be expressed here is a contract conversation, not a local fix.
 */

import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import {
  configuredSlackFixture,
  connectedSlackFixture,
  INTEGRATIONS_SERVER_ERROR_DETAIL,
  SLACK_EXCHANGE_OUTCOME,
  SLACK_OAUTH_CODE,
  SLACK_OAUTH_STATE,
  slackFixture,
} from "@/__tests__/msw/handlers/slack.fixtures";

import {
  CONNECTION_OUTCOME,
  SlackIntegrationHarness,
} from "./slack-integration.harness";

/** The workspace the fixtures connect. */
const WORKSPACE_NAME = "Prowler HQ";

/**
 * The access Prowler asks a workspace for, and nothing else (design D2): post
 * messages, post to a public channel without being invited, and read the
 * channel list — public, plus the private channels the app was invited to.
 */
const REQUIRED_SCOPES = [
  "chat:write",
  "chat:write.public",
  "channels:read",
  "groups:read",
];

describe("starting the install", () => {
  it("sends the user to Slack's consent screen for the access Prowler needs", async () => {
    // Given — a tenant with no workspace connected yet.
    const harness = new SlackIntegrationHarness(slackFixture());
    await harness.mount();

    // When
    const consentScreen = new URL(await harness.connect());

    // Then — Slack's own consent screen, carrying the scopes and the
    // server-minted state that binds this install to the session (design D5).
    expect(`${consentScreen.origin}${consentScreen.pathname}`).toBe(
      "https://slack.com/oauth/v2/authorize",
    );
    expect((consentScreen.searchParams.get("scope") ?? "").split(",")).toEqual(
      expect.arrayContaining(REQUIRED_SCOPES),
    );
    expect(consentScreen.searchParams.get("state")).toBeTruthy();
  }, 30000);

  it("says so when the deployment has no Slack app, instead of offering an install", async () => {
    // Given — a deployment without SLACK_CLIENT_ID/SECRET/REDIRECT_URI, which
    // the API answers with a 503 (contract, "API contract").
    const harness = new SlackIntegrationHarness(
      slackFixture({ appConfigured: false }),
    );

    // When
    await harness.mount();

    // Then — nothing to do and nothing to click, rather than an error.
    await harness.waitForUnavailable();
    expect(harness.offersInstall()).toBe(false);
  }, 30000);

  it("says Slack is busy, not that the deployment has no Slack app, when it is rate limiting", async () => {
    // Given — the app is configured and working; Slack is just rate limiting
    // the call that mints the consent URL.
    const harness = new SlackIntegrationHarness(
      slackFixture({ rateLimited: true }),
    );

    // When
    await harness.mount();

    // Then — the wait is named, and the page does not claim Slack is missing
    // from this environment: that answer would send the user to their admin
    // over something that fixes itself in half a minute.
    expect(await harness.rateLimitNotice()).toMatch(/about 30 seconds/);
    expect(harness.saysUnavailable()).toBe(false);
  }, 30000);

  it("keeps the page usable when reading the install fails on the server", async () => {
    // Given — the shared `GET /integrations` read answers 500. The action lets
    // that surface as a thrown error rather than as a result, so the page has to
    // catch it: uncaught, it reaches the route's error boundary and the user
    // gets an error page instead of the Slack page.
    const harness = new SlackIntegrationHarness(
      slackFixture({ listServerError: true }),
    );

    // When
    await harness.mount();

    // Then — the failure is named in Prowler's words, not in the server's, and
    // the install is still offered: one read failed, the Slack app is fine.
    const notice = await harness.loadErrorNotice();
    expect(notice).toMatch(/temporarily unavailable/);
    expect(notice).not.toMatch(INTEGRATIONS_SERVER_ERROR_DETAIL);
    expect(harness.offersInstall()).toBe(true);
  }, 30000);

  it("names the missing consent URL when a proxy answers that call with an HTML page", async () => {
    // Given — a 200 that is a challenge page rather than the API's JSON.
    // Nothing refused the call, so the action reaches its success path and
    // finds no URL where one was promised.
    const harness = new SlackIntegrationHarness(
      slackFixture({ authorizeUrlUnreadable: true }),
    );

    // When
    await harness.mount();

    // Then — the page says what is missing in Prowler's words. The parser's
    // message for this body is truncated to `"<!DOCTYPE "`, before the word
    // `html`, so nothing downstream could have filtered it out.
    const notice = await harness.loadErrorNotice();
    expect(notice).toMatch(/did not return an authorization URL/);
    expect(notice).not.toMatch(/DOCTYPE/i);
    expect(notice).not.toMatch(/not valid JSON/i);
  }, 30000);
});

describe("returning from Slack", () => {
  it("completes the install and shows the connected workspace", async () => {
    // Given
    const harness = new SlackIntegrationHarness(slackFixture());

    // When — Slack sends the user back with the code it issued.
    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // Then
    expect(await harness.completedInstall()).toBe(true);
    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    // The Slack code is single-use, and the exchange runs from a render
    // (design D4): a second call would burn the code and report a failure for
    // an install that actually succeeded. The once-guard is what prevents it.
    expect(harness.exchangeCallCount).toBe(1);
  }, 30000);

  it("does not report an install the API completed as failed when it answers no content", async () => {
    // Given — the exchange ran to the end: the API validated the state,
    // consumed the code and upserted the integration, then answered `204`.
    // `response.ok` is true, so this is not a refusal — there is simply no body
    // describing what was created.
    const harness = new SlackIntegrationHarness(
      slackFixture({
        exchangeOutcome: SLACK_EXCHANGE_OUTCOME.UNREADABLE_NO_CONTENT,
      }),
    );

    // When
    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // Then — Prowler's own words, pointing at the page that can show the
    // workspace, instead of the parser's "Unexpected end of JSON input".
    const reason = await harness.installFailureReason();
    expect(reason).toMatch(/could not read the result of the install/);
    expect(reason).toMatch(/Slack integration page/);
    expect(reason).not.toMatch(/JSON/i);
    expect(harness.offersRetry()).toBe(true);
    // And the install that *does* exist is not hidden behind a cached "none
    // connected": this outcome keeps the user on the callback, whose only way
    // out is the link to the Slack integration page.
    expect(harness.revalidatedPaths).toEqual(
      expect.arrayContaining(["/integrations", "/integrations/slack"]),
    );
  }, 30000);

  it("shows Prowler's own wording when a proxy answers the completion with an HTML page", async () => {
    // Given — a WAF or gateway answering `200` with a challenge page in place
    // of the API's JSON.
    const harness = new SlackIntegrationHarness(
      slackFixture({ exchangeOutcome: SLACK_EXCHANGE_OUTCOME.UNREADABLE_HTML }),
    );

    // When
    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // Then — nothing of the parser's message reaches the user. This is the one
    // shape no downstream filter can rescue: V8 truncates its message to
    // `Unexpected token '<', "<!DOCTYPE "...`, cutting it off before the word
    // `html`, so the UI's own HTML-shaped-error detection never matches it.
    const reason = await harness.installFailureReason();
    expect(reason).toMatch(/could not read the result of the install/);
    expect(reason).not.toMatch(/DOCTYPE/i);
    expect(reason).not.toMatch(/not valid JSON/i);
  }, 30000);

  it("says the result is unreadable, not that the workspace is unknown, when the answer names no resource", async () => {
    // Given — a `200` carrying well-formed JSON:API with no `data` member.
    const harness = new SlackIntegrationHarness(
      slackFixture({
        exchangeOutcome: SLACK_EXCHANGE_OUTCOME.UNREADABLE_NO_DATA,
      }),
    );

    // When
    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // Then — the page cannot name the workspace, so it does not claim one, and
    // it does not hand the user `"undefined" is not valid JSON` either.
    const reason = await harness.installFailureReason();
    expect(reason).toMatch(/could not read the result of the install/);
    expect(reason).not.toMatch(/undefined/i);
    expect(await harness.completedInstall()).toBe(false);
  }, 30000);

  it("connects nothing when the user declines in Slack, and offers to retry", async () => {
    // Given
    const harness = new SlackIntegrationHarness(slackFixture());

    // When — a declined consent comes back as an error, with no code.
    await harness.mountCallback({ error: "access_denied" });

    // Then
    expect(await harness.installFailureReason()).toMatch(
      /not approved in Slack/,
    );
    expect(harness.offersRetry()).toBe(true);
    // Nothing was created: there was nothing to exchange.
    expect(harness.exchangeCallCount).toBe(0);
  }, 30000);

  it("surfaces the reason when Slack refuses to complete the install", async () => {
    // Given — Slack rejects the code, and the API's own wording explains it.
    const harness = new SlackIntegrationHarness(
      slackFixture({ exchangeOutcome: SLACK_EXCHANGE_OUTCOME.SLACK_REFUSED }),
    );

    // When
    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // Then — a refusal Prowler has nothing better to say about falls back to
    // the API's `detail`, rather than to a generic failure.
    expect(await harness.installFailureReason()).toMatch(
      /OAuth code is invalid/,
    );
    expect(harness.offersRetry()).toBe(true);
  }, 30000);

  it("surfaces a completion the API refuses, and connects nothing", async () => {
    // Given — the state was minted for another session, or already consumed.
    const harness = new SlackIntegrationHarness(
      slackFixture({ exchangeOutcome: SLACK_EXCHANGE_OUTCOME.REFUSED_STATE }),
    );

    // When
    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: "state-from-another-session",
    });

    // Then — the page reports no workspace connected, with the API's reason.
    expect(await harness.installFailureReason()).toMatch(
      /state is invalid, expired, or already consumed/,
    );
    expect(await harness.completedInstall()).toBe(false);
    expect(harness.offersRetry()).toBe(true);
    // Refused once, not retried into a second burnt code.
    expect(harness.exchangeCallCount).toBe(1);
  }, 30000);

  it("says how to resolve a workspace conflict, in Prowler's own words", async () => {
    // Given — this tenant already has a different workspace connected, which
    // the API refuses as a 409 naming the conflict in `code`.
    const harness = new SlackIntegrationHarness(
      slackFixture({
        exchangeOutcome: SLACK_EXCHANGE_OUTCOME.DIFFERENT_WORKSPACE,
      }),
    );

    // When
    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // Then — the copy comes from the code, so it says what to do next; the
    // API's own `detail` states the conflict but not the way out of it.
    const reason = await harness.installFailureReason();
    expect(reason).toMatch(/already connected to a different Slack workspace/);
    expect(reason).toMatch(/Disconnect it before connecting another/);
    expect(reason).not.toMatch(/tenant/);
    expect(await harness.completedInstall()).toBe(false);
    expect(harness.offersRetry()).toBe(true);
  }, 30000);

  it("tells the user when to come back if Slack is rate limiting the install", async () => {
    // Given — Slack answers 429 with a Retry-After.
    const harness = new SlackIntegrationHarness(
      slackFixture({ rateLimited: true }),
    );

    // When
    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // Then — the wait Slack asked for, not a generic failure, and not "Slack
    // isn't available in this environment": the app is there and working.
    const reason = await harness.installFailureReason();
    expect(reason).toMatch(/rate limiting/);
    expect(reason).toMatch(/about 30 seconds/);
    expect(reason).not.toMatch(/not available in this environment/);
    expect(harness.offersRetry()).toBe(true);
  }, 30000);

  it("does not attempt an exchange when the completion carries no state", async () => {
    // Given
    const harness = new SlackIntegrationHarness(slackFixture());

    // When — a return without the value the install started with.
    await harness.mountCallback({ code: SLACK_OAUTH_CODE });

    // Then — refused before the API is ever asked, so no code is spent.
    expect(await harness.installFailureReason()).toMatch(/incomplete response/);
    expect(harness.exchangeCallCount).toBe(0);
  }, 30000);
});

describe("a connected workspace", () => {
  it("identifies the workspace and reports the connection as healthy", async () => {
    // Given — a tenant whose setup is finished: workspace approved and a
    // destination channel recorded, which is what the API needs before it will
    // check a connection at all.
    const harness = new SlackIntegrationHarness(configuredSlackFixture());
    await harness.mount();

    // Then
    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    expect(await harness.connectionBadge()).toBe("Connected");
    expect(await harness.offersConnectionTest()).toBe(true);
    expect(await harness.testConnection()).toBe(CONNECTION_OUTCOME.SUCCESS);
    // One workspace per tenant (design D10): a connected tenant is not invited
    // to install another, and no consent URL is minted for a page that would
    // never use it.
    expect(harness.offersInstall()).toBe(false);
    expect(harness.authorizeUrlCallCount).toBe(0);
  }, 30000);

  it("still identifies the workspace before a destination channel is chosen", async () => {
    // Given — the state the OAuth exchange leaves behind.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());

    // When
    await harness.mount();

    // Then — the configuration carries no channel keys at all, and the page
    // reads that as an install with nothing chosen yet rather than as a broken
    // one.
    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    expect(harness.offersInstall()).toBe(false);
  }, 30000);

  it("reports the connection as never checked, not as broken, before the first check", async () => {
    // Given — the state the OAuth exchange leaves behind: `connected` is null,
    // which is neither true nor false (design.md, "Connection state, in
    // order").
    const harness = new SlackIntegrationHarness(connectedSlackFixture());

    // When
    await harness.mount();

    // Then — the spec calls this connection "neither confirmed working nor
    // reported broken", so a red "Disconnected" beside a heading that says the
    // workspace is connected would report a break nothing has observed.
    const badge = await harness.connectionBadge();
    expect(badge).toBe("Not checked yet");
    expect(badge).not.toMatch(/Disconnected/);
  }, 30000);

  it("does not offer a connection check the API is bound to refuse", async () => {
    // Given — a workspace connected and no destination channel recorded.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());

    // When
    await harness.mount();

    // Then — the check posts to the destination channel, so with none recorded
    // the API answers 400 rather than `connected: false`. Offering the check
    // here would guarantee a failure the user has no way to resolve, so the
    // page names the next step instead.
    expect(await harness.offersConnectionTest()).toBe(false);
    expect(harness.saysChannelIsNextStep()).toBe(true);
  }, 30000);
});
