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
  connectedSlackFixture,
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
    // Given — Slack rejects the code, and its reason travels in the refusal.
    const harness = new SlackIntegrationHarness(
      slackFixture({ exchangeOutcome: SLACK_EXCHANGE_OUTCOME.SLACK_REFUSED }),
    );

    // When
    await harness.mountCallback({
      code: SLACK_OAUTH_CODE,
      state: SLACK_OAUTH_STATE,
    });

    // Then — the user reads what Slack said, not a generic failure.
    expect(await harness.installFailureReason()).toMatch(/invalid_code/);
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
      /could not be matched to the session/,
    );
    expect(await harness.completedInstall()).toBe(false);
    expect(harness.offersRetry()).toBe(true);
    // Refused once, not retried into a second burnt code.
    expect(harness.exchangeCallCount).toBe(1);
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
    // Given — a tenant that already approved Prowler.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();

    // Then
    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    expect(await harness.testConnection()).toBe(CONNECTION_OUTCOME.SUCCESS);
    // One workspace per tenant (design D10): a connected tenant is not invited
    // to install another, and no consent URL is minted for a page that would
    // never use it.
    expect(harness.offersInstall()).toBe(false);
    expect(harness.authorizeUrlCallCount).toBe(0);
  }, 30000);
});
