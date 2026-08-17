/**
 * Browser-mode tests for the Slack integration page (`/integrations/slack`) and
 * its OAuth callback, driven through `SlackIntegrationHarness`. MSW answers
 * from handlers derived from the API contract in `design.md`.
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
 * Callback headlines, spelled out rather than imported so a rename fails here.
 * `FAILURE_TITLE` is for installs that connected nothing; `UNCONFIRMED_TITLE`
 * for answers that arrive after the API already upserted the integration.
 */
const FAILURE_TITLE = "Slack workspace not connected";
const UNCONFIRMED_TITLE = "Slack install not confirmed";

/** The only scopes Prowler asks a workspace for (design D2). */
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

    const consentScreen = new URL(await harness.connect());

    expect(`${consentScreen.origin}${consentScreen.pathname}`).toBe(
      "https://slack.com/oauth/v2/authorize",
    );
    expect((consentScreen.searchParams.get("scope") ?? "").split(",")).toEqual(
      expect.arrayContaining(REQUIRED_SCOPES),
    );
    // The state is server-minted, binding this install to the session
    // (design D5).
    expect(consentScreen.searchParams.get("state")).toBeTruthy();
  }, 30000);

  it("says so when the deployment has no Slack app, instead of offering an install", async () => {
    // Given — no SLACK_CLIENT_ID/SECRET/REDIRECT_URI, which the API answers
    // with a 503.
    const harness = new SlackIntegrationHarness(
      slackFixture({ appConfigured: false }),
    );

    await harness.mount();

    // The read itself succeeded: an empty collection is what a deployment with
    // no Slack app has, so nothing claims it failed.
    await harness.waitForUnavailable();
    expect(harness.offersInstall()).toBe(false);
    expect(harness.saysLoadFailed()).toBe(false);
  }, 30000);

  it("still says the read failed when the deployment also has no Slack app", async () => {
    // Given — both states, which coincide during rollout and rollback
    // (design.md, Migration Plan §2-3 and §5).
    const harness = new SlackIntegrationHarness(
      slackFixture({ appConfigured: false, listServerError: true }),
    );

    await harness.mount();

    // Both notices: the read's is the actionable half (a retry may still show a
    // workspace this tenant has connected).
    const notice = await harness.loadErrorNotice();
    expect(notice).toMatch(/temporarily unavailable/);
    expect(notice).not.toMatch(INTEGRATIONS_SERVER_ERROR_DETAIL);
    expect(harness.saysUnavailable()).toBe(true);
    // The install is still not on offer: there is no Slack app to install into.
    expect(harness.offersInstall()).toBe(false);
  }, 30000);

  it("says Slack is busy, not that the deployment has no Slack app, when it is rate limiting", async () => {
    // Given — the app is configured; Slack rate limits (429) the call that
    // mints the consent URL.
    const harness = new SlackIntegrationHarness(
      slackFixture({ rateLimited: true }),
    );

    await harness.mount();

    expect(await harness.rateLimitNotice()).toMatch(/about 30 seconds/);
    expect(harness.saysUnavailable()).toBe(false);
  }, 30000);

  it("keeps the page usable when reading the install fails on the server", async () => {
    // Given — the shared `GET /integrations` read answers 500. The action
    // throws instead of returning a result, so the page has to catch it:
    // uncaught, the route's error boundary replaces the Slack page.
    const harness = new SlackIntegrationHarness(
      slackFixture({ listServerError: true }),
    );

    await harness.mount();

    const notice = await harness.loadErrorNotice();
    expect(notice).toMatch(/temporarily unavailable/);
    expect(notice).not.toMatch(INTEGRATIONS_SERVER_ERROR_DETAIL);
    // The install stays on offer: one read failed, the Slack app is fine.
    expect(harness.offersInstall()).toBe(true);
  }, 30000);

  it("keeps the page usable when Slack's own side is broken upstream", async () => {
    // Given — the `502` the contract reserves for a Slack upstream failure.
    // The UI's shared 5xx handling throws, so this is the page's other
    // rejection path.
    const harness = new SlackIntegrationHarness(
      slackFixture({ oauthUpstreamError: true }),
    );

    await harness.mount();

    const notice = await harness.loadErrorNotice();
    expect(notice).toMatch(/temporarily unavailable/);
    // 502 is not 503: the app is configured, Slack is down.
    expect(harness.saysUnavailable()).toBe(false);
  }, 30000);

  it("names the missing consent URL when a proxy answers that call with an HTML page", async () => {
    // Given — a 200 carrying a challenge page instead of JSON. Nothing refused
    // the call, so the action reaches its success path with no URL.
    const harness = new SlackIntegrationHarness(
      slackFixture({ authorizeUrlUnreadable: true }),
    );

    await harness.mount();

    // V8 truncates the parse message to `"<!DOCTYPE "`, before the word `html`,
    // so the UI's HTML-shaped-error filter can never match it.
    const notice = await harness.loadErrorNotice();
    expect(notice).toMatch(/did not return an authorization URL/);
    expect(notice).not.toMatch(/DOCTYPE/i);
    expect(notice).not.toMatch(/not valid JSON/i);
  }, 30000);
});

describe("returning from Slack", () => {
  it("completes the install and shows the connected workspace", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    expect(await harness.completedInstall()).toBe(true);
    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    // The code is single-use and the exchange runs from a render (design D4):
    // without the once-guard, a second call burns it and reports a failure.
    expect(harness.exchangeCallCount).toBe(1);
  }, 30000);

  it("does not report an install the API completed as failed when it answers no content", async () => {
    // Given — a `204`: the API consumed the code and upserted the integration,
    // then answered with no body. `response.ok` is true, so this is no refusal.
    const harness = new SlackIntegrationHarness(
      slackFixture({
        exchangeOutcome: SLACK_EXCHANGE_OUTCOME.UNREADABLE_NO_CONTENT,
      }),
    );

    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    const reason = await harness.installFailureReason();
    expect(reason).toMatch(/could not read the result of the install/);
    expect(reason).toMatch(/Slack integration page/);
    expect(reason).not.toMatch(/JSON/i);
    expect(harness.offersRetry()).toBe(true);
    // The `204` says the workspace is connected; the headline cannot deny it.
    expect(await harness.installFailureTitle()).toBe(UNCONFIRMED_TITLE);
    // The install exists, so the cached "none connected" has to go with it.
    expect(harness.revalidatedPaths).toEqual(
      expect.arrayContaining(["/integrations", "/integrations/slack"]),
    );
  }, 30000);

  it("shows Prowler's own wording when a proxy answers the completion with an HTML page", async () => {
    // Given — a proxy answering `200` with a challenge page instead of JSON.
    const harness = new SlackIntegrationHarness(
      slackFixture({ exchangeOutcome: SLACK_EXCHANGE_OUTCOME.UNREADABLE_HTML }),
    );

    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // V8's parse message truncates before the word `html`, so the shared
    // HTML-shaped-error filter cannot catch this one.
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

    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    const reason = await harness.installFailureReason();
    expect(reason).toMatch(/could not read the result of the install/);
    expect(reason).not.toMatch(/undefined/i);
    expect(await harness.completedInstall()).toBe(false);
  }, 30000);

  it("connects nothing when the user declines in Slack, and offers to retry", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountCallback({ error: "access_denied" });

    expect(await harness.installFailureReason()).toMatch(
      /not approved in Slack/,
    );
    expect(harness.offersRetry()).toBe(true);
    // A declined consent carries no code, so there was nothing to exchange.
    expect(harness.exchangeCallCount).toBe(0);
  }, 30000);

  it("surfaces the reason when Slack refuses to complete the install", async () => {
    // Given — Slack rejects the code, and the API's own wording explains it.
    const harness = new SlackIntegrationHarness(
      slackFixture({ exchangeOutcome: SLACK_EXCHANGE_OUTCOME.SLACK_REFUSED }),
    );

    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // A refusal Prowler has no wording of its own for falls back to the API's
    // `detail`, not to a generic failure.
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

    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: "state-from-another-session",
    });

    expect(await harness.installFailureReason()).toMatch(
      /state is invalid, expired, or already consumed/,
    );
    // The API refused before consuming anything, so nothing was created and the
    // headline states that plainly.
    expect(await harness.installFailureTitle()).toBe(FAILURE_TITLE);
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

    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // The copy comes from the error `code`: the API's `detail` states the
    // conflict but not the way out of it.
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

    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    const reason = await harness.installFailureReason();
    expect(reason).toMatch(/rate limiting/);
    expect(reason).toMatch(/about 30 seconds/);
    expect(reason).not.toMatch(/not available in this environment/);
    // A 429 refuses the exchange outright, so nothing was connected: the plain
    // headline, unlike the unreadable `2xx` that arrives after the upsert.
    expect(await harness.installFailureTitle()).toBe(FAILURE_TITLE);
    expect(harness.offersRetry()).toBe(true);
  }, 30000);

  it("reports Slack being broken upstream, rather than leaving the callback spinning", async () => {
    // Given — the completion answers `502`, the contract's status for a Slack
    // upstream failure. The shared 5xx handling throws, so the callback only
    // renders this if the action answers that rejection itself.
    const harness = new SlackIntegrationHarness(
      slackFixture({ oauthUpstreamError: true }),
    );

    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // The API refused, so nothing was created: not the "could not confirm" the
    // page falls back to when the action never answers at all.
    const reason = await harness.installFailureReason();
    expect(reason).toMatch(/temporarily unavailable/);
    expect(reason).not.toMatch(/could not confirm/);
    expect(await harness.completedInstall()).toBe(false);
    expect(harness.offersRetry()).toBe(true);
  }, 30000);

  it("does not attempt an exchange when the completion carries no state", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountCallback({ code: SLACK_OAUTH_CODE });

    // Refused before the API is ever asked, so no code is spent.
    expect(await harness.installFailureReason()).toMatch(/incomplete response/);
    expect(harness.exchangeCallCount).toBe(0);
  }, 30000);
});

describe("a connected workspace", () => {
  it("identifies the workspace and reports the connection as healthy", async () => {
    // Given — a finished setup: workspace approved and a destination channel
    // recorded, which the API requires before it will check a connection.
    const harness = new SlackIntegrationHarness(configuredSlackFixture());
    await harness.mount();

    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    expect(await harness.connectionBadge()).toBe("Connected");
    expect(await harness.offersConnectionTest()).toBe(true);
    expect(await harness.testConnection()).toBe(CONNECTION_OUTCOME.SUCCESS);
    // One workspace per tenant (design D10): no second install on offer, and no
    // consent URL minted for a page that would never use it.
    expect(harness.offersInstall()).toBe(false);
    expect(harness.authorizeUrlCallCount).toBe(0);
  }, 30000);

  it("still identifies the workspace before a destination channel is chosen", async () => {
    // Given — the state the OAuth exchange leaves behind.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());

    await harness.mount();

    // The configuration carries no channel keys at all, which is "nothing
    // chosen yet", not a broken install.
    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    expect(harness.offersInstall()).toBe(false);
  }, 30000);

  it("reports the connection as never checked, not as broken, before the first check", async () => {
    // Given — the state the OAuth exchange leaves behind: `connected` is null,
    // neither true nor false (design.md, "Connection state, in order").
    const harness = new SlackIntegrationHarness(connectedSlackFixture());

    await harness.mount();

    const badge = await harness.connectionBadge();
    expect(badge).toBe("Not checked yet");
    expect(badge).not.toMatch(/Disconnected/);
  }, 30000);

  it("does not offer a connection check the API is bound to refuse", async () => {
    // Given — a workspace connected and no destination channel recorded.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());

    await harness.mount();

    // The check posts to the destination channel, so with none recorded the API
    // answers 400 rather than `connected: false`.
    expect(await harness.offersConnectionTest()).toBe(false);
    expect(harness.saysChannelIsNextStep()).toBe(true);
  }, 30000);
});
