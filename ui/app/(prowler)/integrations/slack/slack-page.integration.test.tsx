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
  disconnectRefusalSlackFixture,
  INTEGRATIONS_SERVER_ERROR_DETAIL,
  partiallyReadSlackFixture,
  revokedTokenSlackFixture,
  revokeFailureSlackFixture,
  SLACK_CHANNEL_NOT_FOUND_REFUSAL,
  SLACK_DISCONNECT_FORBIDDEN_DETAIL,
  SLACK_MISSING_SCOPE_CODE,
  SLACK_MISSING_SCOPE_REFUSAL,
  SLACK_NOT_IN_CHANNEL_CODE,
  SLACK_NOT_IN_CHANNEL_REFUSAL,
  SLACK_PRIVATE_CHANNEL,
  SLACK_PUBLIC_CHANNEL,
  SLACK_RATE_LIMITED_REFUSAL,
  SLACK_SECOND_PUBLIC_CHANNEL,
  SLACK_TOKEN_EXPIRED_CODE,
  SLACK_TOKEN_EXPIRED_REFUSAL,
  SLACK_TOKEN_REVOKED_CODE,
  SLACK_UNKNOWN_CHANNEL_DETAIL,
  SLACK_UPSTREAM_REFUSAL,
  slackFixture,
  slackFixtureWithDefaultChannel,
  unreadableCheckTimeSlackFixture,
  unreportedRevocationSlackFixture,
} from "@/__tests__/msw/handlers/slack.fixtures";

import {
  CONNECTION_OUTCOME,
  REVOCATION_OUTCOME,
  SlackIntegrationHarness,
} from "./slack-integration.harness";

/** The shape the channel save is asserted against — only the id travels. */
interface PatchIntegrationBody {
  data: PatchIntegrationData;
}

interface PatchIntegrationData {
  attributes: PatchIntegrationAttributes;
}

interface PatchIntegrationAttributes {
  configuration: PatchChannelConfiguration;
}

interface PatchChannelConfiguration {
  channel_id: string;
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
    // And — the control itself says what unblocks it.
    expect(harness.connectionCheckBlockedReason()).toMatch(
      /destination channel/i,
    );
  }, 30000);
});

describe("choosing a destination channel", () => {
  it("offers the workspace's channels and remembers the one chosen", async () => {
    // Given — a connected tenant whose channels span two cursor pages.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();

    // Then — every channel is offered, so the picker followed `links.next`
    // rather than stopping at the first page (design D6). Alphabetically: the
    // picker sorts, so the API's page order is not the offered order.
    expect(await harness.channelOptions()).toEqual([
      SLACK_SECOND_PUBLIC_CHANNEL.name,
      SLACK_PUBLIC_CHANNEL.name,
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

  it("narrows the offered channels as the user types", async () => {
    // Given — a connected workspace whose channels were read.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();

    // When — the user types part of a name. Then — only the match stays on
    // offer, so a long workspace list stays navigable.
    const narrowed = await harness.searchChannels("plat");
    expect(narrowed.offered).toEqual([SLACK_SECOND_PUBLIC_CHANNEL.name]);
    expect(narrowed.emptyNote).toBeNull();

    // And — a search matching nothing says so instead of listing channels.
    const none = await harness.searchChannels("no-such-channel");
    expect(none.offered).toEqual([]);
    expect(none.emptyNote).toMatch(/No channel matches/);
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
    expect(await harness.offersConnectionTest()).toBe(false);
  }, 30000);

  it("checks the connection itself as soon as the destination is saved", async () => {
    // Given — connected with nothing recorded: the check posts to the
    // destination, so it is not offered yet.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();
    expect(await harness.offersConnectionTest()).toBe(false);
    expect(harness.connectionCheckBlockedReason()).toMatch(
      /destination channel/i,
    );
    expect(harness.connectionCheckCallCount).toBe(0);

    // When
    await harness.chooseChannel(SLACK_PUBLIC_CHANNEL.name);

    // Then
    expect(await harness.connectionOutcome()).toBe(CONNECTION_OUTCOME.SUCCESS);
    expect(harness.connectionCheckCallCount).toBe(1);
    // And — everything waiting on a destination moves with the save, in the
    // same paint: no reload to find the check on offer for later.
    expect(await harness.offersConnectionTest()).toBe(true);
    expect(harness.connectionCheckBlockedReason()).toBeNull();
  }, 60000);

  it("reports a saved destination the check cannot reach, without losing the save", async () => {
    // Given — a channel the API records, then refuses to reach: the bot is not
    // in it, which only the check finds out.
    const harness = new SlackIntegrationHarness(
      connectedSlackFixture({
        connection: { connected: false, error: SLACK_NOT_IN_CHANNEL_CODE },
      }),
    );
    await harness.mount();

    // When
    await harness.chooseChannel(SLACK_PUBLIC_CHANNEL.name);

    // Then — only the check failed, so the destination stays on record.
    expect(await harness.connectionOutcome()).toBe(CONNECTION_OUTCOME.FAILURE);
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);
    expect(await harness.offersConnectionTest()).toBe(true);
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
    expect(await harness.offersConnectionTest()).toBe(true);
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
    expect(await harness.offersConnectionTest()).toBe(true);
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
    // Alphabetically, as the picker sorts what it offers.
    expect(await harness.channelOptions()).toEqual([
      SLACK_SECOND_PUBLIC_CHANNEL.name,
      SLACK_PUBLIC_CHANNEL.name,
    ]);
    expect(harness.saysChannelsUnreadable()).toBe(false);

    // And — the wait is still said, as the explanation for the short list.
    const notice = harness.partialListNotice();
    expect(notice).toMatch(/rate limiting/);
    expect(notice).toMatch(/about 30 seconds/);

    // And — a partial read says nothing about the destination already recorded.
    expect(await harness.defaultChannel()).toBe(SLACK_PUBLIC_CHANNEL.name);
    expect(await harness.offersConnectionTest()).toBe(true);
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

    // And — nothing was recorded, so there is still nothing to check against.
    expect(await harness.defaultChannel()).toBeNull();
    expect(await harness.offersConnectionTest()).toBe(false);
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

describe("disconnecting a workspace", () => {
  it("removes the integration and returns the card to its unconnected state", async () => {
    // Given — a tenant with a workspace connected.
    const harness = new SlackIntegrationHarness(connectedSlackFixture());
    await harness.mount();

    // When — the user opens the confirmation. Only the removal is Prowler's to
    // promise: the revocation happens at Slack, which can refuse it or report
    // nothing at all.
    expect(await harness.openDisconnectConfirmation()).toBe(
      "Prowler will remove the integration, stop posting to Prowler HQ, and " +
        "attempt to revoke its access at Slack. Connecting again means " +
        "approving Prowler in Slack.",
    );

    // And — the user confirms; Slack confirms the revocation.
    expect(await harness.confirmDisconnect()).toBe(REVOCATION_OUTCOME.REVOKED);

    expect(harness.disconnectCallCount).toBe(1);
    expect(await harness.returnedToUnconnectedState()).toBe(true);
  }, 30000);

  it("still removes the integration when the revocation fails, and says access may need removing by hand", async () => {
    // Given — Slack will not accept the revocation; the row goes either way.
    const harness = new SlackIntegrationHarness(revokeFailureSlackFixture());
    await harness.mount();

    // When
    expect(await harness.disconnect()).toBe(REVOCATION_OUTCOME.NOT_REVOKED);

    // And — the disconnect revalidates, so the copy below is read from props
    // that no longer carry an integration at all.
    await harness.refreshPageData();

    // Then — what is true of both sides: nothing is left in Prowler to retry,
    // and the app may still be installed at Slack.
    const notice = await harness.revocationNotice();
    expect(notice).toMatch(/gone from Prowler/);
    expect(notice).toMatch(/nothing to retry here/);
    expect(notice).toMatch(/may still be installed in Prowler HQ/);
    expect(notice).toMatch(
      /remove it from that workspace's Slack app settings/,
    );
    expect(await harness.returnedToUnconnectedState()).toBe(true);
  }, 30000);

  it("says only that the workspace is no longer connected when nothing reports the revocation", async () => {
    // Given — the plain `204` a deployment that overrides nothing answers: no
    // body, so no `meta` to read the outcome from. The case users really meet.
    const harness = new SlackIntegrationHarness(
      unreportedRevocationSlackFixture(),
    );
    await harness.mount();

    // When
    expect(await harness.disconnect()).toBe(REVOCATION_OUTCOME.UNREPORTED);

    // Then — nothing sends the user to Slack to finish a job no answer said
    // was unfinished.
    expect(harness.showsRevocationNotice()).toBe(false);
    expect(await harness.returnedToUnconnectedState()).toBe(true);
  }, 30000);

  it("says why the disconnect failed and leaves the workspace connected", async () => {
    // Given — a finished setup whose disconnect the API refuses outright, so
    // nothing is removed and Slack is never asked to revoke anything.
    const harness = new SlackIntegrationHarness(
      disconnectRefusalSlackFixture(),
    );
    await harness.mount();

    // When
    const refusal = await harness.refusedDisconnect();

    // Then — the API's own reason reaches the user, and nothing claims a
    // revocation that never ran.
    expect(refusal).toMatch(SLACK_DISCONNECT_FORBIDDEN_DETAIL);
    expect(harness.showsRevocationNotice()).toBe(false);
    // And — the card is untouched: the integration the user still has is the
    // one to try again on.
    expect(await harness.connectedWorkspaceName()).toBe(WORKSPACE_NAME);
    expect(await harness.connectionBadge()).toBe("Connected");
  }, 30000);
});

describe("a credential Slack no longer accepts", () => {
  it("says the connection check found a dead credential, and offers to connect the workspace again", async () => {
    // Given — the token was revoked at Slack, so the row still reads connected
    // until a check runs (contract, Cross-cutting).
    const harness = new SlackIntegrationHarness(revokedTokenSlackFixture());
    await harness.mount();

    // When
    expect(await harness.testConnection()).toBe(CONNECTION_OUTCOME.FAILURE);

    // Then — a way forward rather than only an error: a revoked token is fixed
    // by approving Prowler again, not by checking a second time.
    const notice = await harness.revokedCredentialNotice();
    expect(notice).toMatch(/no longer accepts Prowler's access to Prowler HQ/);
    expect(notice).toMatch(/Prowler's access to Slack was revoked/);
    expect(notice).toMatch(/Connect the workspace again to restore access/);
    // Slack's reason is a protocol token: it is what the UI switched on, never
    // what it showed.
    expect(notice).not.toMatch(new RegExp(SLACK_TOKEN_REVOKED_CODE));

    const consentScreen = new URL(await harness.reconnectUrl());
    expect(`${consentScreen.origin}${consentScreen.pathname}`).toBe(
      "https://slack.com/oauth/v2/authorize",
    );
    await harness.waitForReconnect();
  }, 30000);

  it("offers the same recovery when the channel listing is what finds the credential dead", async () => {
    // Given — a finished setup whose credential expired. The listing runs on
    // arrival, so it meets Slack before any check does, and the contract says
    // any call can be the one that surfaces this.
    const harness = new SlackIntegrationHarness(
      configuredSlackFixture({ channelsRefusal: SLACK_TOKEN_EXPIRED_REFUSAL }),
    );

    // When — nothing but opening the page.
    await harness.mount();

    // Then — the same answer the connection check gives, worded for how this
    // credential died rather than left as a channel problem.
    const notice = await harness.revokedCredentialNotice();
    expect(notice).toMatch(/Prowler's Slack credential has expired/);
    expect(notice).toMatch(/Connect the workspace again to restore access/);
    await harness.waitForReconnect();

    // And — the picker says the same, in the same words: `detail` names the raw
    // reason, and it is `code` the UI answered from.
    const message = await harness.channelPickerMessage();
    expect(message).toMatch(/Prowler's Slack credential has expired/);
    expect(message).not.toMatch(new RegExp(SLACK_TOKEN_EXPIRED_CODE));
  }, 30000);

  it("offers it too when only a later cursor page is what Slack refuses", async () => {
    // Given — a two-page workspace whose second page is refused by a credential
    // Slack no longer accepts: the read stops short rather than failing.
    const harness = new SlackIntegrationHarness(
      partiallyReadSlackFixture({
        channelsRefusal: SLACK_TOKEN_EXPIRED_REFUSAL,
      }),
    );

    // When — nothing but opening the page.
    await harness.mount();

    // Then — what was read stays on offer, as it does for any short list.
    // Alphabetically, as the picker sorts what it offers.
    expect(await harness.channelOptions()).toEqual([
      SLACK_SECOND_PUBLIC_CHANNEL.name,
      SLACK_PUBLIC_CHANNEL.name,
    ]);

    // And — the dead credential is reported all the same: a picker that still
    // works is no reason to leave the user without the one fix there is.
    const notice = await harness.revokedCredentialNotice();
    expect(notice).toMatch(/Prowler's Slack credential has expired/);
    await harness.waitForReconnect();
    expect(await harness.connectionBadge()).toBe("Disconnected");
  }, 60000);

  it("keeps saying so when a later check fails without Slack naming a reason", async () => {
    // Given — the listing found the credential dead on arrival, and a later
    // check that fails naming no reason at all.
    const harness = new SlackIntegrationHarness(
      configuredSlackFixture({
        channelsRefusal: SLACK_TOKEN_EXPIRED_REFUSAL,
        connection: { connected: false, error: null },
      }),
    );
    await harness.mount();
    expect(await harness.revokedCredentialNotice()).toMatch(
      /Prowler's Slack credential has expired/,
    );

    // When
    expect(await harness.testConnection()).toBe(CONNECTION_OUTCOME.FAILURE);

    // Then — a failure Slack never answered is no evidence the grant works
    // again, so the dead credential is still what the page reports.
    expect(await harness.revokedCredentialNotice()).toMatch(
      /Prowler's Slack credential has expired/,
    );
    await harness.waitForReconnect();
    expect(await harness.connectionBadge()).toBe("Disconnected");
  }, 60000);

  it("stops saying so once a save Slack validated goes through", async () => {
    // Given — a finished setup whose connection check found the grant revoked.
    const harness = new SlackIntegrationHarness(
      configuredSlackFixture({
        connection: { connected: false, error: SLACK_TOKEN_REVOKED_CODE },
      }),
    );
    await harness.mount();
    expect(await harness.connectionBadge()).toBe("Connected");
    expect(await harness.testConnection()).toBe(CONNECTION_OUTCOME.FAILURE);
    expect(harness.showsRevokedCredentialNotice()).toBe(true);
    expect(await harness.connectionBadge()).toBe("Disconnected");

    // When — the access is approved again in Slack and the user saves a
    // destination: both the save and the check it runs answer for the grant.
    harness.fixture.connection = { connected: true, error: null };
    await harness.chooseChannel(SLACK_SECOND_PUBLIC_CHANNEL.name);

    // Then — Slack answered, so the notice about a credential it no longer
    // accepts goes, and the card is back to what it reported on arrival.
    expect(harness.showsRevokedCredentialNotice()).toBe(false);
    expect(harness.offersReconnect()).toBe(false);
    expect(await harness.connectionBadge()).toBe("Connected");
  }, 60000);
});
