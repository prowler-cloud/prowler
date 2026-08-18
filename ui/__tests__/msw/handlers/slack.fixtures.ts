/**
 * Fixture data for the Slack handlers. Shapes follow the API contract in
 * `openspec/changes/add-slack-integration/design.md`.
 */

export interface SlackWorkspaceFixture {
  teamId: string;
  teamName: string;
  botUserId: string;
  /**
   * Absent from the serialized configuration until a channel is chosen: the API
   * omits the keys rather than sending nulls.
   */
  channelId?: string;
  channelName?: string;
}

export interface SlackInstallFixture {
  id: string;
  /** `null` until the first connection check runs. */
  connected: boolean | null;
  connectionLastCheckedAt: string | null;
  workspace: SlackWorkspaceFixture;
}

export const SLACK_EXCHANGE_OUTCOME = {
  CREATED: "created",
  /** Same workspace re-installed: the existing row keeps its id. */
  REINSTALLED: "reinstalled",
  REFUSED_STATE: "refused-state",
  SLACK_REFUSED: "slack-refused",
  /** A `409` named by its `code`: one workspace per tenant. */
  DIFFERENT_WORKSPACE: "different-workspace",
  /**
   * The three below are `2xx`: the install happened, but the answer is
   * unreadable, so nothing on the failure path sees them.
   */
  UNREADABLE_NO_CONTENT: "unreadable-no-content",
  UNREADABLE_HTML: "unreadable-html",
  UNREADABLE_NO_DATA: "unreadable-no-data",
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
   * `SLACK_REDIRECT_URI`. Without them every Slack OAuth call answers `503`.
   */
  appConfigured: boolean;
  install: SlackInstallFixture | null;
  exchangeWorkspace: SlackWorkspaceFixture;
  exchangeOutcome: SlackExchangeOutcome;
  connection: SlackConnectionFixture;
  /** The Slack OAuth calls answer `429` with a `Retry-After`. */
  rateLimited: boolean;
  /**
   * The shared `GET /integrations` read answers `500`, which the UI's own
   * helper turns into a thrown error rather than a result.
   */
  listServerError: boolean;
  /** The consent-URL call answers `200` with a proxy's HTML page, not JSON. */
  authorizeUrlUnreadable: boolean;
  /**
   * Both Slack OAuth calls answer `502`, the contract's status for upstream and
   * transport failures. Distinct from `appConfigured: false`, which is a `503`.
   */
  oauthUpstreamError: boolean;
}

export const SLACK_INTEGRATION_ID = "slack-integration-1";

/** The scopes the channel picker and the posting need (design D2). */
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

export const SLACK_AUTHORIZE_URL =
  "https://slack.com/oauth/v2/authorize" +
  "?client_id=1234567890.0987654321" +
  `&scope=${encodeURIComponent(SLACK_BOT_SCOPES.join(","))}` +
  `&state=${SLACK_OAUTH_STATE}` +
  `&redirect_uri=${encodeURIComponent(SLACK_REDIRECT_URI)}`;

/**
 * The `detail` strings the implementation sends. Human copy; the
 * machine-readable reason travels in `code`, which is what the UI maps.
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
 * The `code` on the contract's `502`. The UI maps no copy of its own to it, so
 * the `detail` is what reaches the user.
 */
export const SLACK_UPSTREAM_ERROR_CODE = "service_unavailable";
/**
 * Raised as a `ValidationError({"channel_id": ...})` that still points at
 * `/data` rather than at the attribute.
 */
export const SLACK_NO_CHANNEL_DETAIL =
  "This Slack integration has no channel configured.";
export const SLACK_RATE_LIMITED_DETAIL =
  "Slack is rate limiting requests from Prowler.";
/**
 * What a `500` from the shared `GET /integrations` read carries. Nothing here
 * is for the user to act on, so the UI answers a server error in its own words.
 */
export const INTEGRATIONS_SERVER_ERROR_DETAIL = "A server error occurred.";

/**
 * A `200` challenge page from a proxy or WAF that took the call instead of the
 * API. V8 truncates the parser message for this body before the word `html`, so
 * the UI's own detection (`HTML_ERROR_PATTERN`) cannot recognise it either.
 */
export const PROXY_CHALLENGE_PAGE = [
  "<!DOCTYPE html>",
  "<html><head><title>Attention Required</title></head>",
  "<body><h1>Checking your browser before you proceed.</h1></body></html>",
].join("\n");

/**
 * A wire value, spelled out rather than imported from the UI's own mapping, so
 * a rename on our side fails these tests instead of agreeing with itself.
 */
export const SLACK_WORKSPACE_CONFLICT_CODE = "slack_workspace_conflict";

export const SLACK_RETRY_AFTER_SECONDS = 30;

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
  listServerError: false,
  authorizeUrlUnreadable: false,
  oauthUpstreamError: false,
  ...overrides,
});

/**
 * A workspace approved with no destination channel yet. `connected` is `null`,
 * not `true`: the check runs against the channel, so it has never run
 * (design.md, "Connection state, in order").
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

const configuredInstall = (): SlackInstallFixture => ({
  id: SLACK_INTEGRATION_ID,
  connected: true,
  connectionLastCheckedAt: "2026-08-10T09:30:00Z",
  workspace: {
    ...PROWLER_HQ,
    channelId: SLACK_DEFAULT_CHANNEL.id,
    channelName: SLACK_DEFAULT_CHANNEL.name,
  },
});

/**
 * A workspace connected *and* a channel on record. Anything the API refuses
 * until a channel exists (the connection check) needs this fixture.
 */
export const configuredSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  connectedSlackFixture({ install: configuredInstall(), ...overrides });

/**
 * The same finished setup, with a check time no parser can read: a zero date
 * from a bad write or a serializer change. The contract types the attribute as
 * a string and rules nothing else out.
 */
export const unreadableCheckTimeSlackFixture = (): SlackFixture =>
  connectedSlackFixture({
    install: {
      ...configuredInstall(),
      connectionLastCheckedAt: "0000-00-00T00:00:00Z",
    },
  });
