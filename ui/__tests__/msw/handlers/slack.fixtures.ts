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
  /** The bot the install created, which the API keeps on the configuration. */
  botUserId: string;
  /**
   * The integration's default destination. Both keys are *absent* from the
   * serialized configuration until a channel is chosen — the API omits them
   * rather than sending nulls — so they are optional here for the same reason.
   */
  channelId?: string;
  channelName?: string;
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
  /** Slack itself rejected the code, so the API refuses the completion. */
  SLACK_REFUSED: "slack-refused",
  /**
   * A different workspace is already connected — one per tenant. A `409`,
   * named by its `code`, not a plain refusal.
   */
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
  /**
   * Slack is rate limiting Prowler: the Slack OAuth calls answer `429` with a
   * `Retry-After`, whatever else the fixture says. Handlers added for other
   * Slack-backed endpoints answer the same way.
   */
  rateLimited: boolean;
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

/**
 * The `detail` strings the implementation actually sends. They are human copy,
 * not the machine-readable reason: that travels in `code`, which is what the UI
 * maps. Keeping the real wording here is what makes a test that reads `detail`
 * (an unmapped refusal) honest.
 */
export const SLACK_UNCONFIGURED_DETAIL =
  "Slack integration is not configured or temporarily unavailable.";
export const SLACK_REFUSED_STATE_DETAIL =
  "OAuth state is invalid, expired, or already consumed.";
export const SLACK_INVALID_CODE_DETAIL = "The Slack OAuth code is invalid.";
export const SLACK_DIFFERENT_WORKSPACE_DETAIL =
  "This tenant is already connected to a different Slack workspace.";
export const SLACK_UPSTREAM_DETAIL = "Slack is temporarily unavailable.";
/**
 * Raised as a service-level `ValidationError({"channel_id": ...})`, which still
 * points at `/data` rather than at the attribute.
 */
export const SLACK_NO_CHANNEL_DETAIL =
  "This Slack integration has no channel configured.";
export const SLACK_RATE_LIMITED_DETAIL =
  "Slack is rate limiting requests from Prowler.";

/**
 * The `code` a different-workspace refusal is named by. A wire value, spelled
 * out rather than imported from the UI's own mapping: a rename on our side must
 * fail these tests, not quietly agree with itself.
 */
export const SLACK_WORKSPACE_CONFLICT_CODE = "slack_workspace_conflict";

/** What `Retry-After` carries on a rate-limited answer. */
export const SLACK_RETRY_AFTER_SECONDS = 30;

/** The channel a finished install posts to. */
export const SLACK_DEFAULT_CHANNEL = {
  id: "C0123AB",
  name: "security",
} as const;

const PROWLER_HQ: SlackWorkspaceFixture = {
  teamId: "T01PROWLER",
  teamName: "Prowler HQ",
  botUserId: "U01PROWLERBOT",
};

export const slackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture => ({
  appConfigured: true,
  install: null,
  exchangeWorkspace: { ...PROWLER_HQ },
  exchangeOutcome: SLACK_EXCHANGE_OUTCOME.CREATED,
  connection: { connected: true, error: null },
  rateLimited: false,
  ...overrides,
});

/**
 * A tenant that already approved Prowler in its workspace, and has chosen no
 * destination channel yet — the state the OAuth exchange leaves behind.
 *
 * `connected` is `null`, not `true`: the check runs against the destination
 * channel, so with none recorded it has never run (design.md, "Connection
 * state, in order"). A `true` here would model a state the contract says
 * cannot exist, and would disagree with the exchange handler that mints it.
 */
export const connectedSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  slackFixture({
    install: {
      id: SLACK_INTEGRATION_ID,
      connected: null,
      connectionLastCheckedAt: null,
      workspace: { ...PROWLER_HQ },
    },
    exchangeOutcome: SLACK_EXCHANGE_OUTCOME.REINSTALLED,
    ...overrides,
  });

/**
 * The same tenant with its setup finished: a workspace connected *and* a
 * destination channel on record. Anything the API refuses until a channel
 * exists — the connection check among them — needs this fixture, not the bare
 * connected one.
 */
export const configuredSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  connectedSlackFixture({
    install: {
      id: SLACK_INTEGRATION_ID,
      connected: true,
      connectionLastCheckedAt: "2026-08-10T09:30:00Z",
      workspace: {
        ...PROWLER_HQ,
        channelId: SLACK_DEFAULT_CHANNEL.id,
        channelName: SLACK_DEFAULT_CHANNEL.name,
      },
    },
    ...overrides,
  });
