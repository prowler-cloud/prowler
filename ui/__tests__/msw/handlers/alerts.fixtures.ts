/**
 * Fixture data for the alerts handlers. The alert-rule shapes mirror the API
 * the alerts UI already consumes; the Slack-channel shapes follow the signed
 * contract (`openspec/changes/add-slack-alert-channels/contract/`), addendum
 * section 6 included — it leaves nothing open.
 *
 * The disabled/empty channel states are driven by what the fixture OMITS
 * (no integration, no configured channels, no confirmations), never by
 * handing the UI a pre-disabled state (design D9).
 */

/** A Slack channel configured on the integration. */
export interface AlertsSlackChannelFixture {
  id: string;
  name: string;
  isPrivate: boolean;
  /**
   * Null until the connection check posts its one-time confirmation. Only a
   * confirmed channel is eligible as an alert destination, and a
   * same-workspace reinstall resets every timestamp.
   */
  confirmationSentAt: string | null;
}

/**
 * The tenant's Slack integration. `slackIntegration: null` is the tenant with
 * no workspace connected at all.
 */
export interface AlertsSlackIntegrationFixture {
  id: string;
  workspaceName: string;
  /**
   * Null until a connection check has run; a reinstall or a changed channel
   * set resets it. `true` therefore implies a non-empty set with every channel
   * on it confirmed: the check requires "at least one configured channel" and
   * the integration "is connected only when every check and required
   * confirmation succeeds" (contract, Connection).
   */
  connected: boolean | null;
  /** The channels authorized on the integration. */
  channels: AlertsSlackChannelFixture[];
}

export const ALERT_RULE_TRIGGERS = {
  AFTER_SCAN: "after_scan",
  DAILY: "daily",
  BOTH: "both",
} as const;

export type AlertRuleTriggerFixture =
  (typeof ALERT_RULE_TRIGGERS)[keyof typeof ALERT_RULE_TRIGGERS];

export interface AlertRuleFixture {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  trigger: AlertRuleTriggerFixture;
  /** The condition DSL travels through the UI opaquely. */
  condition: Record<string, unknown>;
  recipientEmails: string[];
  /**
   * Stored destinations, by channel id — all the mapping table holds. The
   * read enriches them from the integration, so an id its workspace no longer
   * carries simply disappears, exactly as the server-side cascade leaves it.
   */
  slackChannelIds: string[];
}

export const ALERT_RECIPIENT_STATUSES = {
  PENDING: "pending",
  CONFIRMED: "confirmed",
  UNSUBSCRIBED: "unsubscribed",
  BOUNCED: "bounced",
} as const;

export type AlertRecipientStatusFixture =
  (typeof ALERT_RECIPIENT_STATUSES)[keyof typeof ALERT_RECIPIENT_STATUSES];

export interface AlertRecipientFixture {
  email: string;
  status: AlertRecipientStatusFixture;
}

export interface AlertsFixture {
  rules: AlertRuleFixture[];
  recipients: AlertRecipientFixture[];
  slackIntegration: AlertsSlackIntegrationFixture | null;
  /** The rules list read answers `500`. */
  listServerError: boolean;
  /**
   * A failure status for `GET /alerts/slack-channels`, or null to serve it.
   * The two statuses reach the UI by different routes: a `5xx` throws out of
   * `handleApiResponse`, a `403` comes back as an error payload. A refused read
   * is also the only route to an empty pool on a connected workspace: served,
   * the pool of a `connected: true` install always holds its confirmed set.
   */
  channelsReadError: number | null;
  /**
   * A failure status for `GET /integrations`, or null to serve it. `403` is
   * the everyday one: the endpoint gates even reads behind
   * `MANAGE_INTEGRATIONS`, which is off by default, while `/alerts` is not
   * gated at all — so a non-admin editing an alert rule always lands here.
   */
  integrationsReadError: number | null;
}

/** UUIDs, as the API's ids are. */
export const ALERTS_SLACK_INTEGRATION_ID =
  "7c9e6a1b-2d3f-4e5a-8b6c-9d0e1f2a3b4c";
export const ALERT_RULE_ID = "1f6d3c2b-8a4e-4b7d-9c5f-0e1a2b3c4d5e";

const CONFIRMED_AT = "2026-08-18T10:15:00Z";

/**
 * The channel ids and names match the Slack fixtures' workspace so an
 * end-to-end reading of both pages tells one story, without importing from
 * `slack.fixtures.ts` (that file belongs to the integrations lane).
 */
export const ALERTS_PUBLIC_CHANNEL: AlertsSlackChannelFixture = {
  id: "C0123AB",
  name: "security",
  isPrivate: false,
  confirmationSentAt: CONFIRMED_AT,
};

export const ALERTS_PRIVATE_CHANNEL: AlertsSlackChannelFixture = {
  id: "C0456CD",
  name: "security-alerts",
  isPrivate: true,
  confirmationSentAt: CONFIRMED_AT,
};

export const ALERTS_CONFIGURED_CHANNELS: AlertsSlackChannelFixture[] = [
  ALERTS_PUBLIC_CHANNEL,
  ALERTS_PRIVATE_CHANNEL,
];

/**
 * The signed refusal code for the rule-write validation (contract section 6.1):
 * one code, and a 400, for every ineligible condition — only the human
 * `detail` says which one refused. Spelled out rather than imported from any
 * UI mapping: a rename on our side must fail these tests.
 */
export const ALERTS_SLACK_CHANNEL_NOT_ELIGIBLE_CODE =
  "slack_channel_not_eligible";

export const ALERTS_SLACK_NOT_CONNECTED_DETAIL =
  "Slack must be connected before an alert rule can name channel destinations.";

export const alertsChannelNotAuthorizedDetail = (channelId: string): string =>
  `Channel ${channelId} is not configured on the Slack integration.`;

export const alertsChannelNotConfirmedDetail = (channelId: string): string =>
  `Channel ${channelId} has not been confirmed yet. Run the Slack connection check first.`;

export const ALERTS_LIST_SERVER_ERROR_DETAIL = "A server error occurred.";

/** DRF's own refusal body, what a read the caller may not perform answers. */
export const ALERTS_READ_FORBIDDEN_DETAIL =
  "You do not have permission to perform this action.";

export const alertRuleFixture = (
  overrides: Partial<AlertRuleFixture> = {},
): AlertRuleFixture => ({
  id: ALERT_RULE_ID,
  name: "Critical findings",
  description: "Notify security when critical findings land.",
  enabled: true,
  trigger: ALERT_RULE_TRIGGERS.AFTER_SCAN,
  condition: {
    op: "count_gte",
    filter: { severity: ["critical"] },
    value: 1,
  },
  recipientEmails: ["security@example.com"],
  slackChannelIds: [],
  ...overrides,
});

/**
 * The baseline tenant: a connected workspace with two confirmed channels (one
 * private) and one email-only rule to edit.
 */
export const alertsFixture = (
  overrides: Partial<AlertsFixture> = {},
): AlertsFixture => ({
  rules: [alertRuleFixture()],
  recipients: [
    {
      email: "security@example.com",
      status: ALERT_RECIPIENT_STATUSES.CONFIRMED,
    },
    { email: "ops@example.com", status: ALERT_RECIPIENT_STATUSES.CONFIRMED },
  ],
  slackIntegration: {
    id: ALERTS_SLACK_INTEGRATION_ID,
    workspaceName: "Prowler HQ",
    connected: true,
    channels: ALERTS_CONFIGURED_CHANNELS.map((channel) => ({ ...channel })),
  },
  listServerError: false,
  channelsReadError: null,
  integrationsReadError: null,
  ...overrides,
});

/** No Slack workspace connected: the channel destination must say why (D9). */
export const noSlackAlertsFixture = (
  overrides: Partial<AlertsFixture> = {},
): AlertsFixture => alertsFixture({ slackIntegration: null, ...overrides });

/**
 * A workspace approved with nothing authorized on it: a new install, or one
 * whose channel set was cleared. `connected` is `null`, never `true` — a check
 * needs at least one configured channel, so none can have run, and clearing the
 * set resets the connection state anyway (contract, Connection and PATCH). The
 * Slack lane models the same tenant in `connectedSlackFixture`.
 */
export const noAuthorizedChannelsAlertsFixture = (
  overrides: Partial<AlertsFixture> = {},
): AlertsFixture =>
  alertsFixture({
    slackIntegration: {
      id: ALERTS_SLACK_INTEGRATION_ID,
      workspaceName: "Prowler HQ",
      connected: null,
      channels: [],
    },
    ...overrides,
  });

/**
 * A same-workspace reinstall: the channels and the rules' mappings survive,
 * every confirmation and the connection state are reset. The only way the API
 * can still hand the form a stored channel it does not offer.
 */
export const reinstalledWorkspaceAlertsFixture = (
  overrides: Partial<AlertsFixture> = {},
): AlertsFixture =>
  alertsFixture({
    slackIntegration: {
      id: ALERTS_SLACK_INTEGRATION_ID,
      workspaceName: "Prowler HQ",
      connected: null,
      channels: ALERTS_CONFIGURED_CHANNELS.map((channel) => ({
        ...channel,
        confirmationSentAt: null,
      })),
    },
    rules: [
      alertRuleFixture({
        slackChannelIds: [ALERTS_PUBLIC_CHANNEL.id, ALERTS_PRIVATE_CHANNEL.id],
      }),
    ],
    ...overrides,
  });
