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
  partiallyReadSlackFixture,
  SLACK_CHANNEL_NOT_FOUND_REFUSAL,
  SLACK_MISSING_SCOPE_CODE,
  SLACK_MISSING_SCOPE_REFUSAL,
  SLACK_NOT_IN_CHANNEL_CODE,
  SLACK_NOT_IN_CHANNEL_REFUSAL,
  SLACK_PRIVATE_CHANNEL,
  SLACK_PUBLIC_CHANNEL,
  SLACK_RATE_LIMITED_REFUSAL,
  SLACK_SECOND_PUBLIC_CHANNEL,
  SLACK_TEST_MESSAGE_REFUSED_DETAIL,
  SLACK_UNKNOWN_CHANNEL_DETAIL,
  SLACK_UNMAPPED_REASON_CODE,
  SLACK_UPSTREAM_REFUSAL,
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
    // Given — a connected tenant whose channels span two cursor pages.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();

    // Then — every channel is offered, so the picker followed `links.next`
    // rather than stopping at the first page (design D6).
    expect(await harness.channelOptions()).toEqual([
      SLACK_PUBLIC_CHANNEL.name,
      SLACK_SECOND_PUBLIC_CHANNEL.name,
      SLACK_PRIVATE_CHANNEL.name,
    ]);
    expect(harness.channelListCallCount).toBe(2);

    // When
    await harness.chooseChannel(SLACK_PUBLIC_CHANNEL.name);

    // Then — only the id is submitted: the API derives the name from it.
    const saved = await harness.lastRequestBody<PatchIntegrationBody>(
      "PATCH",
      "/integrations/",
    );
    expect(saved?.data.attributes.configuration).toEqual({
      channel_id: SLACK_PUBLIC_CHANNEL.id,
    });

    // And — a later visit shows it, under the name the API derived from the id.
    await harness.revisit();
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);
  }, 60000);

  it("offers a private channel the app was invited to, marked as private, and saves it", async () => {
    // Given — `@Prowler` was invited to one private channel; `groups:read` is
    // membership-gated (D2).
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();

    // Then
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
    // Given — a workspace whose only channels are public: `groups:read` is
    // membership-gated (design D2).
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

    // When — `@Prowler` is invited to a private channel, and the user refreshes
    // instead of reconnecting the workspace.
    harness.fixture.channels.push({ ...SLACK_PRIVATE_CHANNEL });
    await harness.refreshChannels();

    // Then
    expect(await harness.channelOptions()).toContain(
      SLACK_PRIVATE_CHANNEL.name,
    );
    expect(
      await harness.isChannelShownAsPrivate(SLACK_PRIVATE_CHANNEL.name),
    ).toBe(true);
  }, 60000);

  it("says what to do when the workspace exposes no channel Prowler can post to", async () => {
    // Given — a connected workspace exposing no channels at all.
    const harness = new SlackIntegrationHarness(
      connectedSlackFixture({ channels: [] }),
    );

    // When
    await harness.mount();

    // Then — the user is told what to do, not merely that the list is empty.
    const message = await harness.channelPickerMessage();
    expect(message).toMatch(/No channels available yet/);
    expect(message).toMatch(/invite @Prowler/);
    expect(await harness.defaultChannel()).toBeNull();
    expect(harness.offersTestMessage()).toBe(false);
  }, 30000);

  it("offers the connection check as soon as the destination is saved, without a revisit", async () => {
    // Given — connected with nothing recorded: the check posts to the
    // destination, so it is not offered yet.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();
    expect(await harness.offersConnectionTest()).toBe(false);
    expect(harness.saysChannelIsNextStep()).toBe(true);

    // When
    await harness.chooseChannel(SLACK_PUBLIC_CHANNEL.name);

    // Then — everything waiting on a destination moves with the save, in the
    // same paint: no reload to find the check on offer.
    expect(await harness.offersConnectionTest()).toBe(true);
    expect(harness.saysChannelIsNextStep()).toBe(false);
    // And — the check really runs.
    expect(await harness.testConnection()).toBe(CONNECTION_OUTCOME.SUCCESS);
  }, 60000);

  it("follows the destination recorded elsewhere when the page's data refreshes under it", async () => {
    // Given — a finished setup, open on screen.
    const harness = new SlackIntegrationHarness(configuredSlackFixture());
    await harness.mount();
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);

    // When — the destination changes elsewhere (a second tab, another user) and
    // this page's server data refreshes under the open card, as
    // `revalidatePath` does after an action.
    await harness.channelRecordedElsewhere(SLACK_SECOND_PUBLIC_CHANNEL.name);
    await harness.refreshPageData();

    // Then — the card reports what is on record, not the copy it took at mount.
    expect(await harness.defaultChannel()).toBe(
      SLACK_SECOND_PUBLIC_CHANNEL.name,
    );
    expect(harness.offersTestMessage()).toBe(true);
    // And — the picker followed too: the superseded destination is not left one
    // click from being saved back.
    expect(harness.offersChannelSave()).toBe(false);
  }, 60000);

  it("says which permission is missing when Slack refuses the channel listing, leaving the recorded channel alone", async () => {
    // Given — a recorded destination, and an install missing a scope the listing
    // needs. The API names it in `code` (contract, Errors), not in `detail`.
    const harness = new SlackIntegrationHarness(
      slackFixtureWithDefaultChannel(SLACK_PUBLIC_CHANNEL, {
        channelsRefusal: SLACK_MISSING_SCOPE_REFUSAL,
      }),
    );

    // When
    await harness.mount();

    // Then — the reason, worded as a fix, with the invite copy still beside the
    // picker.
    const message = await harness.channelPickerMessage();
    expect(message).toMatch(/missing a permission it needs in Slack/);
    expect(message).toMatch(/Connect the workspace again and approve/);
    // Slack's reason is a protocol token: it travels in `code` and is never
    // shown.
    expect(message).not.toMatch(SLACK_MISSING_SCOPE_CODE);
    expect(harness.channelInviteHint()).toMatch(/invites @Prowler/);

    // And — a listing Prowler could not read says nothing about the channel
    // already recorded.
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);
    expect(harness.offersTestMessage()).toBe(true);
  }, 30000);

  it("names the wait Slack asked for when it rate limits the channel listing", async () => {
    // Given — `conversations.list` is Slack tier 2 and paginated (contract,
    // Errors); the `429` carries the wait in `Retry-After`.
    const harness = new SlackIntegrationHarness(
      slackFixtureWithDefaultChannel(SLACK_PUBLIC_CHANNEL, {
        channelsRefusal: SLACK_RATE_LIMITED_REFUSAL,
      }),
    );

    // When
    await harness.mount();

    // Then — when to come back, not just that it was refused: the wait is
    // asserted, not only the wording.
    const message = await harness.channelPickerMessage();
    expect(message).toMatch(/rate limiting/);
    expect(message).toMatch(/about 30 seconds/);

    // And — waiting is the fix, so nothing is said about permissions.
    expect(message).not.toMatch(/permission/);
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);
  }, 30000);

  it("keeps the channels it did read on offer when Slack refuses a later page", async () => {
    // Given — a two-page workspace whose second page is rate limited
    // (`conversations.list` is tier 2, contract, Errors).
    const harness = new SlackIntegrationHarness(partiallyReadSlackFixture());

    // When
    await harness.mount();

    // Then — the picker offers what was read rather than being replaced by the
    // refusal: every reload re-runs the same reads into the same limit.
    expect(await harness.channelOptions()).toEqual([
      SLACK_PUBLIC_CHANNEL.name,
      SLACK_SECOND_PUBLIC_CHANNEL.name,
    ]);
    expect(harness.saysChannelsUnreadable()).toBe(false);

    // And — the wait is still said, as the explanation for the short list.
    const notice = harness.partialListNotice();
    expect(notice).toMatch(/rate limiting/);
    expect(notice).toMatch(/about 30 seconds/);

    // And — a partial read says nothing about the destination already recorded.
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);
    expect(harness.offersTestMessage()).toBe(true);
  }, 60000);

  it("says nothing about a short list when the whole workspace was read", async () => {
    // Given — the default workspace: two cursor pages, read to the end.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());

    // When
    await harness.mount();

    // Then
    expect(harness.partialListNotice()).toBeNull();
  }, 30000);

  it("falls back to the API's wording when the listing fails upstream", async () => {
    // Given — a `502`, which names no `code` because there is nothing to act on
    // (contract, Errors).
    const harness = new SlackIntegrationHarness(
      slackFixtureWithDefaultChannel(SLACK_PUBLIC_CHANNEL, {
        channelsRefusal: SLACK_UPSTREAM_REFUSAL,
      }),
    );

    // When
    await harness.mount();

    // Then — the API's own `detail`, and not a wait that was never promised.
    const message = await harness.channelPickerMessage();
    expect(message).toMatch(/Slack is temporarily unavailable/);
    expect(message).not.toMatch(/rate limiting/);
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);
  }, 30000);

  it("says to invite @Prowler when Slack refuses the channel because the app is not in it", async () => {
    // Given — a private channel the app was removed from. The API validates the
    // channel against Slack on the way in and refuses with `not_in_channel`.
    const harness = new SlackIntegrationHarness(
      connectedSlackFixture({
        channelSaveRefusal: SLACK_NOT_IN_CHANNEL_REFUSAL,
      }),
    );
    await harness.mount();

    // When
    const refusal = await harness.refusedChannelSave(
      SLACK_PRIVATE_CHANNEL.name,
    );

    // Then — the one fix the user can carry out themselves, in Slack.
    expect(refusal).toMatch(/Prowler is not in that channel/);
    expect(refusal).toMatch(/Invite @Prowler to it in Slack/);
    expect(refusal).not.toMatch(SLACK_NOT_IN_CHANNEL_CODE);

    // And — nothing was recorded, so nothing is offered to post with.
    expect(await harness.defaultChannel()).toBeNull();
    expect(harness.offersTestMessage()).toBe(false);
  }, 60000);

  it("says the channel is gone, not that @Prowler needs inviting, when Slack no longer has it", async () => {
    // Given — a channel archived since the listing was read. The API's `detail`
    // is word-for-word the one for `not_in_channel`, so only `code` tells them
    // apart.
    const harness = new SlackIntegrationHarness(
      connectedSlackFixture({
        channelSaveRefusal: SLACK_CHANNEL_NOT_FOUND_REFUSAL,
      }),
    );
    await harness.mount();

    // When
    const refusal = await harness.refusedChannelSave(SLACK_PUBLIC_CHANNEL.name);

    // Then — a different problem, so different copy: nothing to invite to a
    // channel that no longer exists.
    expect(refusal).toMatch(/no longer exists in the workspace/);
    expect(refusal).toMatch(/Choose another one/);
    expect(refusal).not.toMatch(/Invite @Prowler/);
    expect(refusal).not.toMatch(SLACK_UNKNOWN_CHANNEL_DETAIL);
    expect(await harness.defaultChannel()).toBeNull();
  }, 60000);
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
      `#${SLACK_PUBLIC_CHANNEL.name}`,
    );
  }, 60000);

  it("surfaces the reason when Slack refuses the test message", async () => {
    // Given — the post fails, which the API reports on the task it handed back
    // (design D9), not on the request that started it, using the same stable
    // reason the synchronous endpoints put in `code`.
    const harness = new SlackIntegrationHarness(
      connectedSlackFixture({
        testMessage: { accepted: false, error: SLACK_NOT_IN_CHANNEL_CODE },
      }),
    );
    await harness.mount();
    await harness.chooseChannel(SLACK_PUBLIC_CHANNEL.name);

    // When
    const outcome = await harness.sendTestMessage();

    // Then — the same copy the synchronous refusals get, not the raw token.
    expect(outcome).toBe(TEST_MESSAGE_OUTCOME.FAILED);
    const reported = await harness.lastTestMessageOutcome();
    expect(reported).toMatch(/Prowler is not in that channel/);
    expect(reported).toMatch(/Invite @Prowler to it in Slack/);
    expect(reported).not.toMatch(SLACK_NOT_IN_CHANNEL_CODE);
  }, 60000);

  it("reports a refusal the task words itself, rather than swallowing it", async () => {
    // Given — a task result carrying prose instead of a stable reason; its exact
    // shape is the cloud lane's to pin down (contract, test-message).
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

    // Then
    expect(outcome).toBe(TEST_MESSAGE_OUTCOME.FAILED);
    expect(await harness.lastTestMessageOutcome()).toMatch(
      SLACK_TEST_MESSAGE_REFUSED_DETAIL,
    );
  }, 60000);

  it("keeps a reason it has no copy for inside its own sentence, not as the whole message", async () => {
    // Given — a real Slack reason this UI has no copy for; Slack's set is
    // open-ended, so this is the ordinary case.
    const harness = new SlackIntegrationHarness(
      connectedSlackFixture({
        testMessage: { accepted: false, error: SLACK_UNMAPPED_REASON_CODE },
      }),
    );
    await harness.mount();
    await harness.chooseChannel(SLACK_PUBLIC_CHANNEL.name);

    // When
    const outcome = await harness.sendTestMessage();

    // Then — Prowler's wording, with Slack's word for it kept for diagnosis.
    expect(outcome).toBe(TEST_MESSAGE_OUTCOME.FAILED);
    const reported = await harness.lastTestMessageOutcome();
    expect(reported).toMatch(/Slack refused the message/);
    expect(reported).toMatch(SLACK_UNMAPPED_REASON_CODE);
    expect(reported).not.toBe(SLACK_UNMAPPED_REASON_CODE);
  }, 60000);
});
