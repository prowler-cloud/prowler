/**
 * The case `slack-page.integration.test.tsx` cannot express: it asserts against
 * a hydrated, settled page, so it never sees the first frame the user is
 * served. The effect that reads the channels only runs in the browser, so the
 * channel state at render time is what the served HTML says until hydration.
 */

import { renderToString } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { INTEGRATION_TYPE, type IntegrationProps } from "@/types/integrations";

import { SlackIntegrationManager } from "./slack-integration-manager";

vi.mock("@/actions/integrations/slack", () => ({
  getSlackChannels: vi.fn(),
  setSlackDefaultChannel: vi.fn(),
}));

vi.mock("@/actions/integrations/integrations", () => ({
  testIntegrationConnection: vi.fn(),
}));

/**
 * A connected workspace with no channel recorded, as the contract has it before
 * a save: with one, the picker would show that channel instead of the
 * placeholder this test reads.
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

    // Then
    expect(serverHtml).toContain("Reading channels...");
    expect(serverHtml).not.toContain("No channels available yet");
  });
});
