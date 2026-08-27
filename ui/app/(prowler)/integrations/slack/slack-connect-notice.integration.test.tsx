/**
 * Browser-mode tests for the notice the OAuth callback route leaves on the
 * Slack integration page (`/integrations/slack?slack=…`), driven through
 * `SlackIntegrationHarness`. The route handler's own side of the contract —
 * exchanging the code and writing these params — is unit-tested in
 * `callback/route.test.ts`; here the page is opened the way its redirect
 * opens it.
 */

import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import {
  connectedSlackFixture,
  SLACK_RETRY_AFTER_SECONDS,
  SLACK_UNMAPPED_REASON_CODE,
  SLACK_WORKSPACE_CONFLICT_CODE,
  slackFixture,
} from "@/__tests__/msw/handlers/slack.fixtures";

import { SlackIntegrationHarness } from "./slack-integration.harness";

/** The workspace the fixtures connect. */
const WORKSPACE_NAME = "Prowler HQ";

/**
 * Notice headlines, spelled out rather than imported so a rename fails here.
 * `FAILURE_TITLE` is for installs that connected nothing; `UNCONFIRMED_TITLE`
 * for answers that arrived after the API already upserted the integration.
 */
const CONNECTED_TITLE = "Slack workspace connected";
const FAILURE_TITLE = "Slack workspace not connected";
const UNCONFIRMED_TITLE = "Slack install not confirmed";

describe("returning from Slack", () => {
  it("shows the connected workspace with the success notice, and cleans the URL", async () => {
    const harness = new SlackIntegrationHarness(connectedSlackFixture());

    await harness.mountAfterReturnFromSlack({ slack: "connected" });

    expect(await harness.connectNoticeTitle()).toBe(CONNECTED_TITLE);
    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    // The params are spent: a reload or a shared URL shows no stale outcome —
    // while the notice itself survives its own cleanup.
    expect(await harness.strippedQuery()).toBe("");
    expect(harness.hasConnectNotice()).toBe(true);
  }, 30000);

  it("does not claim success when the server lists no connected workspace", async () => {
    // Given - a handcrafted success token but no Slack integration in server data.
    const harness = new SlackIntegrationHarness(slackFixture());

    // When
    await harness.mountAfterReturnFromSlack({ slack: "connected" });

    // Then - the page treats the unverified claim as an unconfirmed install.
    expect(await harness.connectNoticeTitle()).toBe(UNCONFIRMED_TITLE);
    expect(harness.offersInstall()).toBe(true);
  }, 30000);

  it("keeps the query params the notice does not own", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({
      slack: "unconfirmed",
      foo: "bar",
    });

    expect(await harness.connectNoticeTitle()).toBe(UNCONFIRMED_TITLE);
    expect(await harness.strippedQuery()).toBe("?foo=bar");
  }, 30000);

  it("connects nothing when the user declines in Slack, and still offers the install", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({
      slack: "slack_error",
      slack_reason: "access_denied",
    });

    expect(await harness.connectNoticeTitle()).toBe(FAILURE_TITLE);
    expect(await harness.connectNoticeDescription()).toMatch(
      /not approved in Slack/,
    );
    expect(harness.offersInstall()).toBe(true);
  }, 30000);

  it("names a Slack reason it has no wording of its own for", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({
      slack: "slack_error",
      slack_reason: SLACK_UNMAPPED_REASON_CODE,
    });

    expect(await harness.connectNoticeDescription()).toMatch(
      new RegExp(`\\(${SLACK_UNMAPPED_REASON_CODE}\\)`),
    );
  }, 30000);

  it("says the completion was incomplete when Slack sent no usable answer back", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({ slack: "incomplete" });

    expect(await harness.connectNoticeTitle()).toBe(FAILURE_TITLE);
    expect(await harness.connectNoticeDescription()).toMatch(
      /incomplete response/,
    );
  }, 30000);

  it("says a spent install link is done for, not to try again", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({ slack: "expired" });

    expect(await harness.connectNoticeTitle()).toBe(FAILURE_TITLE);
    const description = await harness.connectNoticeDescription();
    expect(description).toMatch(/already been used or expired/);
    expect(description).toMatch(/Start the install again/);
    expect(description).not.toMatch(/in a moment/);
    // The way out it names is on offer right below.
    expect(harness.offersInstall()).toBe(true);
  }, 30000);

  it("says Slack is not available in this environment", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({ slack: "unavailable" });

    expect(await harness.connectNoticeDescription()).toMatch(
      /not available in this environment yet/,
    );
  }, 30000);

  it("tells the user when to come back if Slack rate limited the install", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({
      slack: "rate_limited",
      slack_retry: String(SLACK_RETRY_AFTER_SECONDS),
    });

    expect(await harness.connectNoticeDescription()).toMatch(
      /about 30 seconds/,
    );
  }, 30000);

  it("does not deny an install the API may have completed", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({ slack: "unconfirmed" });

    expect(await harness.connectNoticeTitle()).toBe(UNCONFIRMED_TITLE);
    expect(await harness.connectNoticeDescription()).toMatch(
      /If none is listed below/,
    );
  }, 30000);

  it("keeps Prowler's wording for a refusal the API named by code", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({
      slack: "error",
      slack_code: SLACK_WORKSPACE_CONFLICT_CODE,
    });

    const description = await harness.connectNoticeDescription();
    expect(description).toMatch(
      /already connected to a different Slack workspace/,
    );
    expect(description).toMatch(/Disconnect it before connecting another/);
  }, 30000);

  it("never renders a code it cannot vouch for", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mountAfterReturnFromSlack({
      slack: "error",
      slack_code: "<script>alert(1)</script>",
    });

    const description = await harness.connectNoticeDescription();
    expect(description).toMatch(/could not complete that request/);
    expect(description).not.toMatch(/script|alert/);
  }, 30000);

  it("shows no notice on a plain visit, or for a status it does not recognise", async () => {
    const harness = new SlackIntegrationHarness(slackFixture());

    await harness.mount();
    expect(harness.hasConnectNotice()).toBe(false);

    await harness.mountAfterReturnFromSlack({
      slack: "definitely_not_a_status",
    });
    expect(harness.offersInstall()).toBe(true);
    expect(harness.hasConnectNotice()).toBe(false);
  }, 30000);
});
