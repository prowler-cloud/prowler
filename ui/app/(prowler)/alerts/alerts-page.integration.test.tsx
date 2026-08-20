/**
 * Browser-mode tests for the Alerts page (`/alerts`) and the alert modal's
 * Slack channel destinations, driven through `AlertsPageHarness`. MSW answers
 * from handlers derived from the D3 contract working assumptions
 * (`openspec/changes/add-slack-alert-channels/design.md`).
 *
 * The no-integration and empty-pool states are driven through fixtures that
 * OMIT the integration or its channels (design D9) — never by handing the UI
 * a pre-disabled state.
 */

import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import {
  ALERTS_PRIVATE_CHANNEL,
  ALERTS_PUBLIC_CHANNEL,
  ALERTS_UNAUTHORIZED_CHANNEL,
  alertRuleFixture,
  alertsFixture,
  emptyChannelPoolAlertsFixture,
  noSlackAlertsFixture,
  staleChannelAlertsFixture,
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

  it("offers exactly the integration's authorized set", async () => {
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
    expect(offered).not.toContain(ALERTS_UNAUTHORIZED_CHANNEL.name);
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

  it("says channels must first be authorized when the pool is empty, and still saves", async () => {
    const harness = new AlertsPageHarness(emptyChannelPoolAlertsFixture());
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    expect(await harness.channelFieldState()).toBe(
      CHANNEL_FIELD_STATE.EMPTY_POOL,
    );
    expect(await harness.channelFieldNotice()).toMatch(/authorized/i);
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
            slackChannels: [
              { ...ALERTS_PUBLIC_CHANNEL },
              { ...ALERTS_PRIVATE_CHANNEL },
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

  it("keeps a rule's channels visible after the workspace is disconnected", async () => {
    const harness = new AlertsPageHarness(
      noSlackAlertsFixture({
        rules: [
          alertRuleFixture({
            slackChannels: [
              { ...ALERTS_PUBLIC_CHANNEL },
              { ...ALERTS_PRIVATE_CHANNEL },
            ],
          }),
        ],
      }),
    );
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    expect(await harness.channelFieldState()).toBe(
      CHANNEL_FIELD_STATE.NO_INTEGRATION,
    );
    expect(await harness.selectedChannelChips()).toEqual([
      { name: ALERTS_PUBLIC_CHANNEL.name, isPrivate: false },
      { name: ALERTS_PRIVATE_CHANNEL.name, isPrivate: true },
    ]);
    expect(await harness.channelFieldNotice()).toMatch(
      /unavailable until a Slack workspace is connected/i,
    );
  });

  it("keeps a stored channel selected after it leaves the authorized set", async () => {
    const harness = new AlertsPageHarness(staleChannelAlertsFixture());
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    const chips = await harness.selectedChannelChips();
    expect(chips.map((chip) => chip.name)).toEqual([
      ALERTS_PUBLIC_CHANNEL.name,
      ALERTS_UNAUTHORIZED_CHANNEL.name,
    ]);
    // Merged into the options, so deselecting it is the user's explicit act.
    expect(await harness.offeredChannels()).toContain(
      ALERTS_UNAUTHORIZED_CHANNEL.name,
    );
  });

  it("surfaces the refusal when a saved channel is outside the authorized set", async () => {
    const harness = new AlertsPageHarness(staleChannelAlertsFixture());
    await harness.mount();
    await harness.openEditModal(RULE_NAME);

    const refusal = await harness.refusedRuleSave();

    expect(refusal).toContain(ALERTS_UNAUTHORIZED_CHANNEL.id);
    expect(refusal).toMatch(/authorized/i);
  });
});
