/**
 * Browser-mode tests for the Slack integration page (`/integrations/slack`),
 * driven through `SlackIntegrationHarness`. MSW answers from handlers derived
 * from the API contract in `design.md`. The OAuth callback is its own route,
 * covered in `slack-callback-page.integration.test.tsx`.
 */

import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import {
  configuredSlackFixture,
  connectedSlackFixture,
  INTEGRATIONS_SERVER_ERROR_DETAIL,
  SLACK_CHANNELS_REFUSED_DETAIL,
  SLACK_PRIVATE_CHANNEL,
  SLACK_PUBLIC_CHANNEL,
  SLACK_SECOND_PUBLIC_CHANNEL,
  SLACK_TEST_MESSAGE_REFUSED_DETAIL,
  slackFixture,
  slackFixtureWithDefaultChannel,
  unreadableCheckTimeSlackFixture,
} from "@/__tests__/msw/handlers/slack.fixtures";

import {
  CONNECTION_OUTCOME,
  SlackIntegrationHarness,
  TEST_MESSAGE_OUTCOME,
} from "./slack-integration.harness";

/** The shape the channel save is asserted against — only the id travels. */
interface PatchIntegrationBody {
  data: { attributes: { configuration: { channel_id: string } } };
}

/** The workspace the fixtures connect. */
const WORKSPACE_NAME = "Prowler HQ";

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
    const scopes = (consentScreen.searchParams.get("scope") ?? "").split(",");
    expect(scopes).toHaveLength(REQUIRED_SCOPES.length);
    expect(scopes).toEqual(expect.arrayContaining(REQUIRED_SCOPES));
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

  it("keeps the page usable when the recorded check time is one no parser can read", async () => {
    // Given — a finished setup whose `connection_last_checked_at` is a zero
    // date. `date-fns` throws a RangeError on it, which would replace the whole
    // page with the route's error boundary.
    const harness = new SlackIntegrationHarness(
      unreadableCheckTimeSlackFixture(),
    );

    await harness.mount();

    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    expect(await harness.connectionBadge()).toBe("Connected");
    // Nothing to show, so nothing is shown: the same line a workspace that was
    // never checked renders.
    expect(harness.lastCheckedLine()).toBeNull();
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

describe("choosing a destination channel", () => {
  it("offers the workspace's channels and remembers the one chosen", async () => {
    // Given — a connected tenant, whose workspace exposes more channels than
    // fit on one cursor page.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();

    // Then — every channel is offered, so the picker followed `links.next`
    // rather than stopping at the first page (design D6, Slack's listing is
    // paginated and rate-limited).
    expect(await harness.channelOptions()).toEqual([
      SLACK_PUBLIC_CHANNEL.name,
      SLACK_SECOND_PUBLIC_CHANNEL.name,
      SLACK_PRIVATE_CHANNEL.name,
    ]);
    expect(harness.channelListCallCount).toBe(2);

    // When
    await harness.chooseChannel(SLACK_PUBLIC_CHANNEL.name);

    // Then — only the id is submitted: the API validates it against Slack and
    // derives the name, so a name sent from here could only ever drift.
    const saved = await harness.lastRequestBody<PatchIntegrationBody>(
      "PATCH",
      "/integrations/",
    );
    expect(saved?.data.attributes.configuration).toEqual({
      channel_id: SLACK_PUBLIC_CHANNEL.id,
    });

    // And — a later visit shows it as the destination, under the name the API
    // derived from the id rather than one the UI remembered locally.
    await harness.revisit();
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);
  }, 60000);

  it("offers a private channel the app was invited to, marked as private, and saves it", async () => {
    // Given — `@Prowler` has been invited to one private channel, which is
    // what makes it visible at all (`groups:read` is membership-gated, D2).
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();

    // Then — it is offered, and the user can tell it apart from a public one.
    expect(await harness.channelOptions()).toContain(
      SLACK_PRIVATE_CHANNEL.name,
    );
    expect(
      await harness.isChannelShownAsPrivate(SLACK_PRIVATE_CHANNEL.name),
    ).toBe(true);
    expect(
      await harness.isChannelShownAsPrivate(SLACK_PUBLIC_CHANNEL.name),
    ).toBe(false);

    // When
    await harness.chooseChannel(SLACK_PRIVATE_CHANNEL.name);

    // Then
    expect(await harness.defaultChannel()).toBe(SLACK_PRIVATE_CHANNEL.name);
  }, 60000);

  it("offers a private channel once @Prowler is invited to it and the list is refreshed", async () => {
    // Given — a workspace whose only channels are public. `groups:read` is
    // membership-gated (design D2), so a private channel the app has not been
    // invited to does not exist as far as Prowler is concerned.
    const harness = new SlackIntegrationHarness(
      connectedSlackFixture({
        channels: [
          { ...SLACK_PUBLIC_CHANNEL },
          { ...SLACK_SECOND_PUBLIC_CHANNEL },
        ],
      }),
    );
    await harness.mount();
    expect(await harness.channelOptions()).not.toContain(
      SLACK_PRIVATE_CHANNEL.name,
    );

    // When — someone invites `@Prowler` to a private channel in Slack, and the
    // user refreshes instead of reconnecting the workspace.
    harness.fixture.channels.push({ ...SLACK_PRIVATE_CHANNEL });
    await harness.refreshChannels();

    // Then — it joins the list, still marked as private.
    expect(await harness.channelOptions()).toContain(
      SLACK_PRIVATE_CHANNEL.name,
    );
    expect(
      await harness.isChannelShownAsPrivate(SLACK_PRIVATE_CHANNEL.name),
    ).toBe(true);
  }, 60000);

  it("says what to do when the workspace exposes no channel Prowler can post to", async () => {
    // Given — a freshly connected workspace the app has not been invited to
    // anywhere, with no public channel either.
    const harness = new SlackIntegrationHarness(
      connectedSlackFixture({ channels: [] }),
    );

    // When
    await harness.mount();

    // Then — the user is told what to do, not merely that the list is empty,
    // and nothing is recorded.
    const message = await harness.channelPickerMessage();
    expect(message).toMatch(/No channels available yet/);
    expect(message).toMatch(/invite @Prowler/);
    expect(await harness.defaultChannel()).toBeNull();
    expect(harness.offersTestMessage()).toBe(false);
  }, 30000);

  it("surfaces Slack's reason when it refuses the channel listing, leaving the recorded channel alone", async () => {
    // Given — a tenant that already recorded a destination.
    const harness = new SlackIntegrationHarness(
      slackFixtureWithDefaultChannel(SLACK_PUBLIC_CHANNEL, {
        channelsError: SLACK_CHANNELS_REFUSED_DETAIL,
      }),
    );

    // When
    await harness.mount();

    // Then — the reason Slack reported, and the invite copy stays next to the
    // picker so the fix is still one sentence away.
    expect(await harness.channelPickerMessage()).toMatch(/ratelimited/);
    expect(harness.channelInviteHint()).toMatch(/invites @Prowler/);

    // And — a listing Prowler could not read says nothing about the channel
    // already on the integration: it stays recorded, and still postable to.
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);
    expect(harness.offersTestMessage()).toBe(true);
  }, 30000);
});

describe("sending a test message", () => {
  it("is not offered until a destination channel is recorded", async () => {
    // Given — connected, but no channel chosen yet.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());

    // When
    await harness.mount();

    // Then
    expect(await harness.defaultChannel()).toBeNull();
    expect(harness.offersTestMessage()).toBe(false);
  }, 30000);

  it("sends a test message to the recorded channel and reports it delivered", async () => {
    // Given — a tenant that has recorded where Prowler should post.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();
    await harness.chooseChannel(SLACK_PUBLIC_CHANNEL.name);

    // When
    const outcome = await harness.sendTestMessage();

    // Then — sent, and the user reads which channel it went to.
    expect(outcome).toBe(TEST_MESSAGE_OUTCOME.SENT);
    expect(await harness.lastTestMessageOutcome()).toMatch(
      new RegExp(`#${SLACK_PUBLIC_CHANNEL.name}`),
    );
  }, 60000);

  it("surfaces the reason when Slack refuses the test message", async () => {
    // Given — the post itself fails, which the API reports on the task it
    // handed back (design D9), not on the request that started it.
    const harness = new SlackIntegrationHarness(
      connectedSlackFixture({
        testMessage: {
          accepted: false,
          error: SLACK_TEST_MESSAGE_REFUSED_DETAIL,
        },
      }),
    );
    await harness.mount();
    await harness.chooseChannel(SLACK_PUBLIC_CHANNEL.name);

    // When
    const outcome = await harness.sendTestMessage();

    // Then — Slack's own reason, not a generic failure.
    expect(outcome).toBe(TEST_MESSAGE_OUTCOME.FAILED);
    expect(await harness.lastTestMessageOutcome()).toMatch(/channel_not_found/);
  }, 60000);
});
