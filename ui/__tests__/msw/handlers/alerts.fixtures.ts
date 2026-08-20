/**
 * Fixture data for the alerts handlers. The alert-rule shapes mirror the API
 * the alerts UI already consumes; the Slack-channel shapes follow the working
 * assumptions in `openspec/changes/add-slack-alert-channels/design.md` (D3) —
 * every assumed wire name carries a `TODO(Josema)` in `./alerts.ts` until the
 * contract is signed off.
 *
 * The disabled/empty channel states are driven by what the fixture OMITS
 * (no integration, no authorized channels), never by handing the UI a
 * pre-disabled state (design D9).
 */

/** A Slack channel as the alerts surfaces know one: id, name, privacy. */
export interface AlertsSlackChannelFixture {
  id: string;
  name: string;
  isPrivate: boolean;
}

/**
 * The connected Slack integration as the alert form reads it — only the
 * authorized destination set matters on this page. `slackIntegration: null`
 * is the no-workspace-connected tenant.
 */
export interface AlertsSlackIntegrationFixture {
  id: string;
  workspaceName: string;
  authorizedChannels: AlertsSlackChannelFixture[];
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
   * Stored destinations with resolved name and privacy. May include channels
   * absent from the integration's authorized set — the stale-channel
   * scenario, which the UI must keep visible rather than silently drop.
   */
  slackChannels: AlertsSlackChannelFixture[];
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
}

/** UUIDs, as the API's ids are. */
export const ALERTS_SLACK_INTEGRATION_ID =
  "7c9e6a1b-2d3f-4e5a-8b6c-9d0e1f2a3b4c";
export const ALERT_RULE_ID = "1f6d3c2b-8a4e-4b7d-9c5f-0e1a2b3c4d5e";

/**
 * The channel ids and names match the Slack fixtures' workspace so an
 * end-to-end reading of both pages tells one story, without importing from
 * `slack.fixtures.ts` (that file belongs to the integrations lane).
 */
export const ALERTS_PUBLIC_CHANNEL: AlertsSlackChannelFixture = {
  id: "C0123AB",
  name: "security",
  isPrivate: false,
};

export const ALERTS_PRIVATE_CHANNEL: AlertsSlackChannelFixture = {
  id: "C0456CD",
  name: "security-alerts",
  isPrivate: true,
};

/** Offered by the workspace but NOT authorized: stale-channel material. */
export const ALERTS_UNAUTHORIZED_CHANNEL: AlertsSlackChannelFixture = {
  id: "C0789EF",
  name: "platform",
  isPrivate: false,
};

export const ALERTS_AUTHORIZED_CHANNELS: AlertsSlackChannelFixture[] = [
  ALERTS_PUBLIC_CHANNEL,
  ALERTS_PRIVATE_CHANNEL,
];

/**
 * Refusal wire values for the rule-write validation, spelled out rather than
 * imported from any UI mapping: a rename on our side must fail these tests.
 * TODO(Josema): status/code of both refusals pending contract sign-off (D3).
 */
export const ALERTS_CHANNEL_NOT_AUTHORIZED_CODE =
  "slack_channel_not_authorized";
export const ALERTS_SLACK_NOT_CONNECTED_CODE = "slack_not_connected";

export const ALERTS_SLACK_NOT_CONNECTED_DETAIL =
  "Slack must be connected before an alert rule can name channel destinations.";

export const alertsChannelNotAuthorizedDetail = (channelId: string): string =>
  `Channel ${channelId} is not in the Slack integration's authorized channels.`;

export const ALERTS_LIST_SERVER_ERROR_DETAIL = "A server error occurred.";

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
  slackChannels: [],
  ...overrides,
});

/**
 * The baseline tenant: a connected workspace with two authorized channels
 * (one private) and one email-only rule to edit.
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
    authorizedChannels: ALERTS_AUTHORIZED_CHANNELS.map((channel) => ({
      ...channel,
    })),
  },
  listServerError: false,
  ...overrides,
});

/** No Slack workspace connected: the channel destination must say why (D9). */
export const noSlackAlertsFixture = (
  overrides: Partial<AlertsFixture> = {},
): AlertsFixture => alertsFixture({ slackIntegration: null, ...overrides });

/** Workspace connected, nothing authorized yet: the empty-pool state (D9). */
export const emptyChannelPoolAlertsFixture = (
  overrides: Partial<AlertsFixture> = {},
): AlertsFixture =>
  alertsFixture({
    slackIntegration: {
      id: ALERTS_SLACK_INTEGRATION_ID,
      workspaceName: "Prowler HQ",
      authorizedChannels: [],
    },
    ...overrides,
  });

/**
 * A rule that stored a channel the integration no longer authorizes: the
 * stored value must stay visible and selected, and a re-save keeping it must
 * be refused by the ⊆ validation.
 */
export const staleChannelAlertsFixture = (
  overrides: Partial<AlertsFixture> = {},
): AlertsFixture =>
  alertsFixture({
    rules: [
      alertRuleFixture({
        slackChannels: [
          { ...ALERTS_PUBLIC_CHANNEL },
          { ...ALERTS_UNAUTHORIZED_CHANNEL },
        ],
      }),
    ],
    ...overrides,
  });
