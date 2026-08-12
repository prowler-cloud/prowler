/**
 * Browser-mode tests for the integrations catalogue (`/integrations`).
 *
 * Slack is a Prowler Cloud feature — its API only exists in the cloud
 * deployment — so the catalogue offers it there and nowhere else. That gate is
 * the whole of this page's Slack behaviour, which is why these two tests are
 * the whole file.
 *
 * The page is driven through `SlackIntegrationHarness`, the shared harness for
 * the Slack flow: the catalogue is where that flow starts.
 */

import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import { slackFixture } from "@/__tests__/msw/handlers/slack.fixtures";

import { SlackIntegrationHarness } from "./slack/slack-integration.harness";

describe("the integrations catalogue", () => {
  it("offers Slack in Prowler Cloud, with a way to manage it", async () => {
    // Given — a Prowler Cloud deployment (the fixtures' default island).
    const harness = new SlackIntegrationHarness(slackFixture());

    // When
    harness.mountCatalogue();

    // Then
    expect(await harness.listedIntegrations()).toContain("Slack");
    expect(harness.offersSlackManagement()).toBe(true);
  }, 30000);

  it("omits Slack in a deployment that is not Prowler Cloud", async ({
    seedRuntimeConfig,
  }) => {
    // Given
    seedRuntimeConfig({ cloudEnabled: false });
    const harness = new SlackIntegrationHarness(slackFixture());

    // When
    harness.mountCatalogue();

    // Then — Slack is gone, and nothing offers to manage it.
    const listed = await harness.listedIntegrations();
    expect(listed).not.toContain("Slack");
    expect(harness.offersSlackManagement()).toBe(false);
    // Tripwire: the catalogue itself still rendered, so the assertion above is
    // Slack being absent rather than the page failing to load.
    expect(listed).toContain("Jira");
  }, 30000);
});
