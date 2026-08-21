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

/** A channel the listing endpoint offers for the picker. */
export interface SlackChannelFixture {
  id: string;
  name: string;
  /** Private channels are listed only where `@Prowler` has been invited. */
  isPrivate: boolean;
}

/**
 * A refusal as the API sends one: the machine-readable reason in `code`, human
 * copy in `detail`, and — for a `429` — the wait in `Retry-After`.
 */
export interface SlackRefusalFixture {
  status: number;
  /** Slack's stable reason. `null` for the failures classified by status. */
  code: string | null;
  detail: string;
  /** Seconds `Retry-After` asked for; only a `429` carries one. */
  retryAfterSeconds: number | null;
}

/**
 * What `DELETE /integrations/{id}` reports about revoking the token at Slack.
 * Revocation is best-effort: the row goes either way, and the outcome travels in
 * JSON:API `meta`.
 *
 * One boolean is the whole of it: the API sends no reason for a revocation that
 * did not happen, so modelling one would let a test prove copy the real
 * deployment can never produce.
 */
export interface SlackRevocationFixture {
  /**
   * Slack confirmed the token no longer grants Prowler anything. `null` when the
   * answer reports nothing at all — the plain `204` a deployment without a
   * `destroy` override sends, which is what the UI meets today.
   */
  revoked: boolean | null;
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
  channels: SlackChannelFixture[];
  /**
   * Small on purpose: the default workspace spans two pages, so a UI that
   * stopped at `data` instead of following `links.next` would lose channels.
   */
  channelsPageSize: number;
  /** Slack refused the listing outright, with the reason named in `code`. */
  channelsRefusal: SlackRefusalFixture | null;
  /**
   * The cursor the refusal starts at. Absent, the whole read fails; a page
   * size serves the first page and refuses the second — the partial read.
   */
  channelsRefusalFromCursor?: number;
  /**
   * Slack refused the chosen channel when the `PATCH` validated it — the
   * listing itself answered fine.
   */
  channelSaveRefusal: SlackRefusalFixture | null;
  /**
   * The API refused the disconnect itself, so the row is still there
   * afterwards. Distinct from `revocation`, which is about a removal that
   * happened.
   */
  disconnectRefusal: SlackRefusalFixture | null;
  revocation: SlackRevocationFixture;
}

/**
 * A UUID, as the API's ids are: it travels in the URL of every Slack call and
 * the actions accept no other shape.
 */
export const SLACK_INTEGRATION_ID = "7c9e6a1b-2d3f-4e5a-8b6c-9d0e1f2a3b4c";

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
export const SLACK_MISSING_SCOPE_DETAIL =
  "Slack refused the request: missing_scope.";
/**
 * Names the raw reason, as the missing-scope wording does: what lets a test tell
 * copy the UI mapped from `code` apart from an echoed `detail`.
 */
export const SLACK_TOKEN_EXPIRED_DETAIL =
  "Slack refused the request: token_expired.";
/**
 * The same sentence for "it is gone" and "the app was removed from it": only
 * `code` separates them, which is why a client must read `code`.
 */
export const SLACK_UNKNOWN_CHANNEL_DETAIL =
  "That channel is not one Prowler can post to.";

/**
 * A `403` from the shared destroy route: the role can read the integration but
 * not remove it. Names no Slack reason, so the API's own wording is what the
 * user is shown.
 */
export const SLACK_DISCONNECT_FORBIDDEN_DETAIL =
  "You do not have permission to disconnect this integration.";

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
 * The `code` values the refusals below are named by. Wire values, spelled out
 * rather than imported from the UI's own mapping: a rename on our side must
 * fail these tests, not quietly agree with itself.
 */
export const SLACK_WORKSPACE_CONFLICT_CODE = "slack_workspace_conflict";
export const SLACK_MISSING_SCOPE_CODE = "missing_scope";
export const SLACK_CHANNEL_NOT_FOUND_CODE = "channel_not_found";
export const SLACK_NOT_IN_CHANNEL_CODE = "not_in_channel";
/**
 * A reason Slack really sends that the UI's mapping does not cover — the set is
 * open-ended, so having no copy for one is the ordinary case.
 */
export const SLACK_UNMAPPED_REASON_CODE = "is_archived";
/**
 * Two of the four dead-grant codes the contract lists. Whichever call surfaces
 * one, the integration is disconnected and the only way out is connecting the
 * workspace again (contract, Cross-cutting).
 */
export const SLACK_TOKEN_REVOKED_CODE = "token_revoked";
export const SLACK_TOKEN_EXPIRED_CODE = "token_expired";

export const SLACK_RETRY_AFTER_SECONDS = 30;

/** The install never granted a scope the call needs: actionable, so a `400`. */
export const SLACK_MISSING_SCOPE_REFUSAL: SlackRefusalFixture = {
  status: 400,
  code: SLACK_MISSING_SCOPE_CODE,
  detail: SLACK_MISSING_SCOPE_DETAIL,
  retryAfterSeconds: null,
};

/**
 * Where this really happens is the channel listing: `conversations.list` is
 * tier 2 and paginated.
 */
export const SLACK_RATE_LIMITED_REFUSAL: SlackRefusalFixture = {
  status: 429,
  code: null,
  detail: SLACK_RATE_LIMITED_DETAIL,
  retryAfterSeconds: SLACK_RETRY_AFTER_SECONDS,
};

/**
 * The stored grant is no longer usable: a `400` like any other actionable
 * refusal, deliberately not the `401` that would read as an expired Prowler
 * session (contract, Errors).
 */
export const SLACK_TOKEN_EXPIRED_REFUSAL: SlackRefusalFixture = {
  status: 400,
  code: SLACK_TOKEN_EXPIRED_CODE,
  detail: SLACK_TOKEN_EXPIRED_DETAIL,
  retryAfterSeconds: null,
};

/** Slack-side or transport failure — a `502` naming no reason at all. */
export const SLACK_UPSTREAM_REFUSAL: SlackRefusalFixture = {
  status: 502,
  code: null,
  detail: SLACK_UPSTREAM_DETAIL,
  retryAfterSeconds: null,
};

/** The chosen channel is archived, deleted, or was never in the workspace. */
export const SLACK_CHANNEL_NOT_FOUND_REFUSAL: SlackRefusalFixture = {
  status: 400,
  code: SLACK_CHANNEL_NOT_FOUND_CODE,
  detail: SLACK_UNKNOWN_CHANNEL_DETAIL,
  retryAfterSeconds: null,
};

/**
 * The channel is fine, the Prowler app is simply not in it — fixed with
 * `/invite @Prowler`. Identical `detail` to the refusal above, deliberately.
 */
export const SLACK_NOT_IN_CHANNEL_REFUSAL: SlackRefusalFixture = {
  status: 400,
  code: SLACK_NOT_IN_CHANNEL_CODE,
  detail: SLACK_UNKNOWN_CHANNEL_DETAIL,
  retryAfterSeconds: null,
};

/** The disconnect is refused before Slack is asked anything: a `403`. */
export const SLACK_DISCONNECT_FORBIDDEN_REFUSAL: SlackRefusalFixture = {
  status: 403,
  code: null,
  detail: SLACK_DISCONNECT_FORBIDDEN_DETAIL,
  retryAfterSeconds: null,
};

/**
 * Two public channels and one private the Prowler app was invited to, ordered
 * so the private one lands on the second cursor page.
 */
export const SLACK_PUBLIC_CHANNEL: SlackChannelFixture = {
  id: "C0123AB",
  name: "security",
  isPrivate: false,
};

export const SLACK_SECOND_PUBLIC_CHANNEL: SlackChannelFixture = {
  id: "C0789EF",
  name: "platform",
  isPrivate: false,
};

export const SLACK_PRIVATE_CHANNEL: SlackChannelFixture = {
  id: "C0456CD",
  name: "security-alerts",
  isPrivate: true,
};

export const SLACK_CHANNELS: SlackChannelFixture[] = [
  SLACK_PUBLIC_CHANNEL,
  SLACK_SECOND_PUBLIC_CHANNEL,
  SLACK_PRIVATE_CHANNEL,
];

/** Two channels per page, so `SLACK_CHANNELS` spans exactly two pages. */
export const SLACK_CHANNELS_PAGE_SIZE = 2;

/**
 * The first channel the picker offers, so an install seeded with it always
 * points at a channel the listing really has.
 */
export const SLACK_DEFAULT_CHANNEL = SLACK_PUBLIC_CHANNEL;

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
  channels: SLACK_CHANNELS.map((channel) => ({ ...channel })),
  channelsPageSize: SLACK_CHANNELS_PAGE_SIZE,
  channelsRefusal: null,
  channelSaveRefusal: null,
  disconnectRefusal: null,
  revocation: { revoked: true },
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

const configuredInstall = (
  channel: SlackChannelFixture = SLACK_DEFAULT_CHANNEL,
): SlackInstallFixture => ({
  id: SLACK_INTEGRATION_ID,
  connected: true,
  connectionLastCheckedAt: "2026-08-10T09:30:00Z",
  workspace: {
    ...PROWLER_HQ,
    channelId: channel.id,
    channelName: channel.name,
  },
});

/**
 * The same tenant with a destination channel already on record: the state a
 * second visit starts from.
 */
export const slackFixtureWithDefaultChannel = (
  channel: SlackChannelFixture = SLACK_PUBLIC_CHANNEL,
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  connectedSlackFixture({ install: configuredInstall(channel), ...overrides });

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

/**
 * The first cursor page is served and Slack rate limits the second: what is
 * already read stays usable, the refusal only says why the list is short.
 */
export const partiallyReadSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  slackFixtureWithDefaultChannel(SLACK_PUBLIC_CHANNEL, {
    channelsRefusal: SLACK_RATE_LIMITED_REFUSAL,
    channelsRefusalFromCursor: SLACK_CHANNELS_PAGE_SIZE,
    ...overrides,
  });

/**
 * A workspace connected *and* a channel on record. Anything the API refuses
 * until a channel exists (the connection check) needs this fixture.
 */
export const configuredSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  slackFixtureWithDefaultChannel(SLACK_DEFAULT_CHANNEL, overrides);

/**
 * A connected tenant whose disconnect removes the row but cannot revoke at
 * Slack — the outcome the user has to finish by hand in the workspace.
 */
export const revokeFailureSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  connectedSlackFixture({
    revocation: { revoked: false },
    ...overrides,
  });

/**
 * A connected tenant whose disconnect answers a plain `204` with no body: the
 * row is gone and the revocation is unreported.
 */
export const unreportedRevocationSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  connectedSlackFixture({
    revocation: { revoked: null },
    ...overrides,
  });

/**
 * A connected tenant whose disconnect the API refuses: nothing is removed and
 * nothing is revoked, so the workspace is still connected afterwards.
 */
export const disconnectRefusalSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  configuredSlackFixture({
    disconnectRefusal: SLACK_DISCONNECT_FORBIDDEN_REFUSAL,
    ...overrides,
  });

/**
 * A connected tenant whose token has been revoked at Slack: the row still says
 * connected until a check runs, and the check is what surfaces it.
 */
export const revokedTokenSlackFixture = (
  overrides: Partial<SlackFixture> = {},
): SlackFixture =>
  configuredSlackFixture({
    connection: { connected: false, error: SLACK_TOKEN_REVOKED_CODE },
    ...overrides,
  });
