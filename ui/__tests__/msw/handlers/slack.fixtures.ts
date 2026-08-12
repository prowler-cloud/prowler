/**
 * Fixture data for the Slack integration handlers.
 *
 * A fixture describes a world — "this deployment has no Slack app", "this
 * tenant already connected Prowler HQ", "the exchange will be refused" — and
 * `handlersForSlack` serves it. The shapes are derived from the API contract in
 * `openspec/changes/add-slack-integration/design.md`; that contract, not this
 * file, is where a disagreement with the deployed backend gets settled.
 */

export interface SlackWorkspaceFixture {
  teamId: string;
  teamName: string;
  /** The integration's default destination, null until one is chosen. */
  channelId: string | null;
  channelName: string | null;
}

export interface SlackInstallFixture {
  id: string;
  /** `null` until the first connection check runs, as the API upserts it. */
  connected: boolean | null;
  connectionLastCheckedAt: string | null;
  workspace: SlackWorkspaceFixture;
}

export const SLACK_EXCHANGE_OUTCOME = {
  /** First install for the tenant: the exchange creates the integration. */
  CREATED: "created",
  /** The same workspace re-installed: the existing row keeps its id. */
  REINSTALLED: "reinstalled",
  /** The API could not match the `state` it minted, so it refuses. */
  REFUSED_STATE: "refused-state",
  /** Slack itself rejected the code; its reason travels in `detail`. */
  SLACK_REFUSED: "slack-refused",
  /** A different workspace is already connected — one per tenant. */
  DIFFERENT_WORKSPACE: "different-workspace",
} as const;

export type SlackExchangeOutcome =
  (typeof SLACK_EXCHANGE_OUTCOME)[keyof typeof SLACK_EXCHANGE_OUTCOME];

export interface SlackConnectionFixture {
  connected: boolean;
  error: string | null;
}

export interface SlackFixture {
  /**
   * The deployment has `SLACK_CLIENT_ID` / `SLACK_CLIENT_SECRET` /
   * `SLACK_REDIRECT_URI`. Without them every Slack OAuth call answers 503.
   */
  appConfigured: boolean;
  /** The workspace this tenant has already connected, if any. */
  install: SlackInstallFixture | null;
  /** The workspace an exchange connects. */
  exchangeWorkspace: SlackWorkspaceFixture;
  exchangeOutcome: SlackExchangeOutcome;
  /** What a connection check reports. */
  connection: SlackConnectionFixture;
}

export const SLACK_INTEGRATION_ID = "slack-integration-1";

/** Exactly the scopes D2 justifies — the picker and the posting need no more. */
export const SLACK_BOT_SCOPES = [
  "chat:write",
  "chat:write.public",
  "channels:read",
  "groups:read",
] as const;

export const SLACK_REDIRECT_URI =
  "https://cloud.prowler.com/integrations/slack/callback";

/** Server-minted, single-use, bound to the tenant and user (design D5). */
export const SLACK_OAUTH_STATE = "st-2f1c9d7a";
export const SLACK_OAUTH_CODE = "slack-code-1f4a";

/** The consent URL the API returns, with the state already inside it. */
export const SLACK_AUTHORIZE_URL =
  "https://slack.com/oauth/v2/authorize" +
  "?client_id=1234567890.0987654321" +
  `&scope=${encodeURIComponent(SLACK_BOT_SCOPES.join(","))}` +
  `&state=${SLACK_OAUTH_STATE}` +
  `&redirect_uri=${encodeURIComponent(SLACK_REDIRECT_URI)}`;

export const SLACK_UNCONFIGURED_DETAIL =
  "Slack is not configured for this deployment.";
export const SLACK_REFUSED_STATE_DETAIL =
  "This install could not be matched to the session that started it.";
export const SLACK_INVALID_CODE_DETAIL =
  "Slack rejected the install: invalid_code.";
export const SLACK_DIFFERENT_WORKSPACE_DETAIL =
  "Another Slack workspace is already connected. Disconnect it first.";

const PROWLER_HQ: SlackWorkspaceFixture = {
  teamId: "T01PROWLER",
  teamName: "Prowler HQ",
  channelId: null,
  channelName: null,
};

export const slackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture => ({
  appConfigured: true,
  install: null,
  exchangeWorkspace: { ...PROWLER_HQ },
  exchangeOutcome: SLACK_EXCHANGE_OUTCOME.CREATED,
  connection: { connected: true, error: null },
  ...overrides,
});

/** A tenant that already approved Prowler in its workspace. */
export const connectedSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  slackFixture({
    install: {
      id: SLACK_INTEGRATION_ID,
      connected: true,
      connectionLastCheckedAt: "2026-08-10T09:30:00Z",
      workspace: { ...PROWLER_HQ },
    },
    exchangeOutcome: SLACK_EXCHANGE_OUTCOME.REINSTALLED,
    ...overrides,
  });
