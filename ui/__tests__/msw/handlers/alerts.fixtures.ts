/**
 * Fixture data for the alerts handlers. The Slack-channel shapes follow the
 * signed contract (`openspec/changes/add-slack-alert-channels/contract/`).
 *
 * The disabled/empty channel states are driven by what the fixture OMITS
 * (no integration, no configured channels, no confirmations), never by
 * handing the UI a pre-disabled state (design D9).
 */

export interface AlertsSlackChannelFixture {
  id: string;
  name: string;
  isPrivate: boolean;
  /**
   * Null until the connection check posts its confirmation; a same-workspace
   * reinstall resets every timestamp. Only a confirmed channel is eligible.
   */
  confirmationSentAt: string | null;
}

/** `slackIntegration: null` is a tenant with no workspace connected at all. */
export interface AlertsSlackIntegrationFixture {
  id: string;
  workspaceName: string;
  /**
   * Null until a connection check has run; a reinstall or a changed channel
   * set resets it. `true` therefore implies a non-empty set with every channel
   * on it confirmed (contract, Connection).
   */
  connected: boolean | null;
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
  /** Ids only; the read enriches them from the integration. */
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
   * A failure status for `GET /alerts/slack-channels`, or null to serve it. A
   * refused read is the only route to an empty pool on a connected workspace:
   * served, a `connected: true` install always holds its confirmed set.
   */
  channelsReadError: number | null;
  /**
   * A failure status for `GET /integrations`, or null to serve it. `403` is
   * the everyday one: the endpoint gates even reads behind
   * `MANAGE_INTEGRATIONS`, off by default, while `/alerts` is not gated — a
   * non-admin editing an alert rule always lands here.
   */
  integrationsReadError: number | null;
}

export const ALERTS_SLACK_INTEGRATION_ID =
  "7c9e6a1b-2d3f-4e5a-8b6c-9d0e1f2a3b4c";
export const ALERT_RULE_ID = "1f6d3c2b-8a4e-4b7d-9c5f-0e1a2b3c4d5e";

const CONFIRMED_AT = "2026-08-18T10:15:00Z";

/**
 * Ids and names match the Slack fixtures' workspace, deliberately without
 * importing from `slack.fixtures.ts` (the integrations lane owns that file).
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
 * One code, and a 400, for every ineligible condition (contract section 6.1) —
 * only the human `detail` says which one refused. Code and details are spelled
 * out here rather than imported from the UI: a rename on our side must fail
 * these tests.
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

/** DRF's own refusal body. */
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
 * The baseline tenant: a connected workspace with two confirmed channels and
 * one email-only rule.
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
 * A workspace approved with nothing authorized on it. `connected` is `null`,
 * never `true`: a check needs at least one configured channel, so none can
 * have run, and clearing the set resets the connection state anyway
 * (contract, Connection and PATCH).
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
 * every confirmation and the connection state are reset — the only way the API
 * can hand the form a stored channel it does not offer.
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
