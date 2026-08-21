/**
 * Browser-mode tests for the Alerts page (`/alerts`) and the alert modal's
 * Slack channel destinations, driven through `AlertsPageHarness`. MSW answers
 * from handlers encoding the signed contract
 * (`openspec/changes/add-slack-alert-channels/contract/slack-alerts-api.md`).
 *
 * The no-integration and empty-pool states are driven through fixtures that
 * OMIT the integration, its channels or their confirmations (design D9) —
 * never by handing the UI a pre-disabled state.
 */

import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import {
  ALERTS_PRIVATE_CHANNEL,
  ALERTS_PUBLIC_CHANNEL,
  alertRuleFixture,
  alertsChannelNotConfirmedDetail,
  alertsFixture,
  emptyChannelPoolAlertsFixture,
  noSlackAlertsFixture,
  reinstalledWorkspaceAlertsFixture,
} from "@/__tests__/msw/handlers/alerts.fixtures";

import { AlertsPageHarness, CHANNEL_FIELD_STATE } from "./alerts-page.harness";

const RULE_NAME = "Critical findings";

interface RuleWriteBody {
  data: { attributes: { recipient_emails?: string[] } };
}

describe("alert rules target Slack channels", () => {
  it("creates a rule with channels and an email, keeping both destination kinds", async () => {
    const harness = new AlertsPageHarness(alertsFixture());
    harness.mountCreateEntry();
    await harness.openCreateModal();

    await harness.pickChannels([
      ALERTS_PUBLIC_CHANNEL.name,
      ALERTS_PRIVATE_CHANNEL.name,
    ]);
    await harness.pickRecipients(["security@example.com"]);
    await harness.saveRule();

    expect(await harness.savedRuleChannels()).toEqual([
      ALERTS_PUBLIC_CHANNEL.id,
      ALERTS_PRIVATE_CHANNEL.id,
    ]);
    const body = await harness.lastRequestBody<RuleWriteBody>(
      "POST",
      "/alerts/rules",
    );
    expect(body?.data.attributes.recipient_emails).toContain(
      "security@example.com",
    );
  });

  it("accepts a rule whose only destinations are channels", async () => {
    const harness = new AlertsPageHarness(alertsFixture());
    harness.mountCreateEntry();
    await harness.openCreateModal();

    await harness.pickChannels([ALERTS_PRIVATE_CHANNEL.name]);
    await harness.saveRule();

    expect(await harness.savedRuleChannels()).toEqual([
      ALERTS_PRIVATE_CHANNEL.id,
    ]);
    const body = await harness.lastRequestBody<RuleWriteBody>(
      "POST",
      "/alerts/rules",
    );
    expect(body?.data.attributes.recipient_emails).toEqual([]);
  });

  it("offers exactly the eligible channels", async () => {
    const harness = new AlertsPageHarness(alertsFixture());
    harness.mountCreateEntry();
    await harness.openCreateModal();

    const offered = await harness.offeredChannels();

    expect(offered).toEqual(
      expect.arrayContaining([
        ALERTS_PUBLIC_CHANNEL.name,
        ALERTS_PRIVATE_CHANNEL.name,
      ]),
    );
    expect(offered).toHaveLength(2);
  });

  it("identifies a private channel in the listing and on its chip", async () => {
    const harness = new AlertsPageHarness(alertsFixture());
    harness.mountCreateEntry();
    await harness.openCreateModal();

    expect(
      await harness.isChannelOfferedAsPrivate(ALERTS_PRIVATE_CHANNEL.name),
    ).toBe(true);
    expect(
      await harness.isChannelOfferedAsPrivate(ALERTS_PUBLIC_CHANNEL.name),
    ).toBe(false);

    await harness.pickChannels([ALERTS_PRIVATE_CHANNEL.name]);

    expect(await harness.selectedChannelChips()).toEqual([
      { name: ALERTS_PRIVATE_CHANNEL.name, isPrivate: true },
    ]);
  });

  it("says channels must be authorized and checked when nothing is eligible, and still saves", async () => {
    const harness = new AlertsPageHarness(emptyChannelPoolAlertsFixture());
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    expect(await harness.channelFieldState()).toBe(
      CHANNEL_FIELD_STATE.EMPTY_POOL,
    );
    const notice = await harness.channelFieldNotice();
    expect(notice).toMatch(/authorize/i);
    expect(notice).toMatch(/connection check/i);
    expect(harness.integrationAffordanceHref()).toBe("/integrations/slack");

    // The rule's other fields and destinations still save.
    await harness.saveRule();
    expect(await harness.savedRuleChannels()).toEqual([]);
  });

  it("explains the disabled destination when no workspace is connected", async () => {
    const harness = new AlertsPageHarness(noSlackAlertsFixture());
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    expect(await harness.channelFieldState()).toBe(
      CHANNEL_FIELD_STATE.NO_INTEGRATION,
    );
    expect(await harness.channelPickerDisabled()).toBe(true);
    // Deleting the workspace deletes the rules' channel mappings with it.
    expect(await harness.selectedChannelChips()).toEqual([]);
    expect(await harness.channelFieldNotice()).toMatch(
      /connected Slack workspace/i,
    );
    expect(harness.integrationAffordanceHref()).toBe("/integrations/slack");
  });

  it("shows the stored selection, by name and privacy, when editing", async () => {
    const harness = new AlertsPageHarness(
      alertsFixture({
        rules: [
          alertRuleFixture({
            slackChannelIds: [
              ALERTS_PUBLIC_CHANNEL.id,
              ALERTS_PRIVATE_CHANNEL.id,
            ],
          }),
        ],
      }),
    );
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    expect(await harness.channelFieldState()).toBe(
      CHANNEL_FIELD_STATE.POPULATED,
    );
    expect(await harness.selectedChannelChips()).toEqual([
      { name: ALERTS_PUBLIC_CHANNEL.name, isPrivate: false },
      { name: ALERTS_PRIVATE_CHANNEL.name, isPrivate: true },
    ]);
  });

  it("submits the complete selection, not just the added channel", async () => {
    const harness = new AlertsPageHarness(
      alertsFixture({
        rules: [
          alertRuleFixture({ slackChannelIds: [ALERTS_PUBLIC_CHANNEL.id] }),
        ],
      }),
    );
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    await harness.pickChannels([ALERTS_PRIVATE_CHANNEL.name]);
    await harness.saveRule();

    expect(await harness.savedRuleChannels()).toEqual([
      ALERTS_PUBLIC_CHANNEL.id,
      ALERTS_PRIVATE_CHANNEL.id,
    ]);
  });

  it("keeps a stored channel readable after a reinstall reset its confirmation", async () => {
    const harness = new AlertsPageHarness(reinstalledWorkspaceAlertsFixture());
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    // The workspace still carries both channels, but an unverified install
    // offers none of them: the options come from the eligible-channels
    // endpoint, never from the integration's configuration.
    expect(await harness.channelFieldState()).toBe(
      CHANNEL_FIELD_STATE.NO_INTEGRATION,
    );
    expect(await harness.channelPickerDisabled()).toBe(true);
    expect(await harness.selectedChannelChips()).toEqual([
      { name: ALERTS_PUBLIC_CHANNEL.name, isPrivate: false },
      { name: ALERTS_PRIVATE_CHANNEL.name, isPrivate: true },
    ]);
  });

  it("saves an edit that retains channels a reinstall left unconfirmed", async () => {
    const harness = new AlertsPageHarness(reinstalledWorkspaceAlertsFixture());
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    await harness.saveRule();

    // Only newly added channels are validated, so the retained selection goes
    // back untouched even though the reinstall confirmed none of it — a rule
    // never becomes uneditable behind the user's back.
    expect(await harness.savedRuleChannels()).toEqual([
      ALERTS_PUBLIC_CHANNEL.id,
      ALERTS_PRIVATE_CHANNEL.id,
    ]);
  });

  it("surfaces the refusal when a channel just added went stale before the save", async () => {
    const fixture = alertsFixture();
    const harness = new AlertsPageHarness(fixture);
    await harness.mount();
    await harness.openEditModal(RULE_NAME);
    await harness.pickChannels([ALERTS_PRIVATE_CHANNEL.name]);

    // The picker offered a confirmed channel; the connection state it was
    // offered on is reset before the submit. Only a channel the user just
    // added can reach the write ineligible, so this is the one path a refusal
    // travels.
    fixture.slackIntegration?.channels.forEach((channel) => {
      if (channel.id === ALERTS_PRIVATE_CHANNEL.id) {
        channel.confirmationSentAt = null;
      }
    });

    const refusal = await harness.refusedRuleSave();

    // The modal stays open on the unchanged rule and repeats the API's own
    // detail, which the UI never parses.
    expect(refusal).toContain(
      alertsChannelNotConfirmedDetail(ALERTS_PRIVATE_CHANNEL.id),
    );
  });
});

describe("the alerts list shows destinations", () => {
  it("shows a rule's channels by name alongside its emails, without opening it", async () => {
    const harness = new AlertsPageHarness(
      alertsFixture({
        rules: [
          alertRuleFixture({
            slackChannelIds: [
              ALERTS_PUBLIC_CHANNEL.id,
              ALERTS_PRIVATE_CHANNEL.id,
            ],
          }),
        ],
      }),
    );
    await harness.mount();

    expect(await harness.ruleDestinationsSummary(RULE_NAME)).toBe(
      `security@example.com · #${ALERTS_PUBLIC_CHANNEL.name} +1 more`,
    );
  });

  it("reads correctly for emails-only, channels-only and empty rules", async () => {
    const harness = new AlertsPageHarness(
      alertsFixture({
        rules: [
          alertRuleFixture({ id: "rule-emails", name: "Emails only" }),
          alertRuleFixture({
            id: "rule-channels",
            name: "Channels only",
            recipientEmails: [],
            slackChannelIds: [ALERTS_PRIVATE_CHANNEL.id],
          }),
          alertRuleFixture({
            id: "rule-none",
            name: "No destinations yet",
            recipientEmails: [],
          }),
        ],
      }),
    );
    await harness.mount();

    expect(await harness.ruleDestinationsSummary("Emails only")).toBe(
      "security@example.com",
    );
    expect(await harness.ruleDestinationsSummary("Channels only")).toBe(
      `#${ALERTS_PRIVATE_CHANNEL.name}`,
    );
    expect(await harness.ruleDestinationsSummary("No destinations yet")).toBe(
      "No destinations",
    );
  });
});
