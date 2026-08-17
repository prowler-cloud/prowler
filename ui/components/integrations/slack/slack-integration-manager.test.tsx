/**
 * The case `slack-page.integration.test.tsx` cannot express: it asserts against
 * a hydrated, settled page, so it never sees the frame the user is served
 * first. The manager is a client component rendered on the server by an async
 * server component with nothing suspending in front of it, and the effect that
 * reads the channels only runs in the browser — so whatever the channel state
 * says at render time is what the served HTML says for the whole
 * first-paint→hydration window.
 */

import { renderToString } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { INTEGRATION_TYPE, type IntegrationProps } from "@/types/integrations";

import { SlackIntegrationManager } from "./slack-integration-manager";

vi.mock("@/actions/integrations/slack", () => ({
  getSlackChannels: vi.fn(),
  sendSlackTestMessage: vi.fn(),
  setSlackDefaultChannel: vi.fn(),
}));

vi.mock("@/actions/integrations/integrations", () => ({
  testIntegrationConnection: vi.fn(),
}));

/**
 * A healthy workspace with no destination channel chosen yet — the channel keys
 * are absent, as the contract has them before a save. No channel is recorded on
 * purpose: with one, the picker shows that channel instead of its placeholder,
 * and the placeholder is what carries the "still reading" claim.
 */
const CONNECTED_WORKSPACE: IntegrationProps = {
  type: "integrations",
  id: "slack-integration-1",
  attributes: {
    inserted_at: "2026-08-10T09:00:00Z",
    updated_at: "2026-08-10T09:00:00Z",
    enabled: true,
    connected: true,
    connection_last_checked_at: "2026-08-10T09:05:00Z",
    integration_type: INTEGRATION_TYPE.SLACK,
    configuration: {
      team_id: "T024BE7LD",
      team_name: "Prowler HQ",
      bot_user_id: "U0KRQLJ9H",
    },
  },
  links: { self: "/api/v1/integrations/slack-integration-1" },
};

describe("the first paint of a connected workspace", () => {
  it("reads as still reading the channels rather than as a workspace with none", () => {
    // When
    const serverHtml = renderToString(
      <SlackIntegrationManager
        integration={CONNECTED_WORKSPACE}
        authorizeUrl={null}
        unavailable={false}
        rateLimitMessage={null}
        loadError={null}
      />,
    );

    // Then - the empty-list alert would tell a user with channels to go create
    // one in Slack, and it is the only thing the picker's slot could hold that
    // makes a claim about the workspace.
    expect(serverHtml).toContain("Reading channels...");
    expect(serverHtml).not.toContain("No channels available yet");
  });
});
