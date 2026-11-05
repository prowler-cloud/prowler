/**
 * Browser-mode tests for the Slack entry in the integrations catalogue
 * (`/integrations`), which is offered in Prowler Cloud only. Driven through
 * `SlackIntegrationHarness` against the MSW handlers.
 */

import { describe, expect } from "vitest";

import { it } from "@/__tests__/fixtures";
import { slackFixture } from "@/__tests__/msw/handlers/slack.fixtures";

import { SlackIntegrationHarness } from "./slack/slack-integration.harness";

describe("the integrations catalogue", () => {
  it("offers Slack in Prowler Cloud, with a way to manage it", async () => {
    // Given — a Prowler Cloud deployment (the fixtures' default island).
    const harness = new SlackIntegrationHarness(slackFixture());

    harness.mountCatalogue();

    expect(await harness.listedIntegrations()).toContain("Slack");
    expect(harness.offersSlackManagement()).toBe(true);
  }, 30000);

  it("omits Slack in a deployment that is not Prowler Cloud", async ({
    seedRuntimeConfig,
  }) => {
    seedRuntimeConfig({ cloudEnabled: false });
    const harness = new SlackIntegrationHarness(slackFixture());

    harness.mountCatalogue();

    const listed = await harness.listedIntegrations();
    expect(listed).not.toContain("Slack");
    expect(harness.offersSlackManagement()).toBe(false);
    // Tripwire: the catalogue rendered, so the assertions above are Slack's
    // absence rather than the page failing to load.
    expect(listed).toContain("Jira");
  }, 30000);
});
