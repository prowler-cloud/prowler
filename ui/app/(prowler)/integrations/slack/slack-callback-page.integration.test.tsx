/**
 * Browser-mode tests for the Slack OAuth callback
 * (`/integrations/slack/callback`), driven through `SlackIntegrationHarness`.
 * MSW answers from handlers derived from the API contract in `design.md`.
 */

import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import {
  SLACK_EXCHANGE_OUTCOME,
  SLACK_OAUTH_CODE,
  SLACK_OAUTH_STATE,
  slackFixture,
} from "@/__tests__/msw/handlers/slack.fixtures";

import { SlackIntegrationHarness } from "./slack-integration.harness";

/** The workspace the fixtures connect. */
const WORKSPACE_NAME = "Prowler HQ";

/**
 * Callback headlines, spelled out rather than imported so a rename fails here.
 * `FAILURE_TITLE` is for installs that connected nothing; `UNCONFIRMED_TITLE`
 * for answers that arrive after the API already upserted the integration.
 */
const FAILURE_TITLE = "Slack workspace not connected";
const UNCONFIRMED_TITLE = "Slack install not confirmed";

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
    // A completed install invalidates the cached "none connected".
    expect(harness.revalidatedPaths).toEqual(
      expect.arrayContaining(["/integrations", "/integrations/slack"]),
    );
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
