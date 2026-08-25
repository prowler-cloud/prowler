/**
 * MSW handlers for the alerts pages: rules CRUD, recipients, the eligible
 * Slack channels the destination field offers, the integration read that
 * tells an empty pool from no workspace at all, and the sibling reads the
 * alerts page issues on mount (providers, scans, findings metadata).
 *
 * The Slack shapes follow the signed contract
 * (`openspec/changes/add-slack-alert-channels/contract/slack-alerts-api.md`,
 * section 2 and the section 6 addendum, which closed every open point).
 *
 * State is per-call: a create is visible to the next rules read. Wire them
 * per test via `worker.use(...handlersForAlerts(fx))`.
 */

import { http, HttpResponse } from "msw";

import {
  ALERTS_LIST_SERVER_ERROR_DETAIL,
  ALERTS_READ_FORBIDDEN_DETAIL,
  ALERTS_SLACK_CHANNEL_NOT_ELIGIBLE_CODE,
  ALERTS_SLACK_NOT_CONNECTED_DETAIL,
  alertsChannelNotAuthorizedDetail,
  alertsChannelNotConfirmedDetail,
} from "./alerts.fixtures";
import type {
  AlertRuleFixture,
  AlertsFixture,
  AlertsSlackChannelFixture,
} from "./alerts.fixtures";

const API = process.env.UI_API_BASE_URL;
const TS = "2026-08-20T09:00:00Z";

/**
 * `status` is a string, per the JSON:API spec — same taxonomy the Slack
 * handlers answer with, since the validation is about Slack state.
 */
const errorBody = (detail: string, status: number, code?: string) => ({
  errors: [
    {
      status: String(status),
      ...(code ? { code } : {}),
      detail,
      source: { pointer: "/data" },
    },
  ],
});

/**
 * A read the fixture asks to fail. The status is the whole point: a `5xx`
 * throws out of `handleApiResponse` and rejects the caller's promise, a `4xx`
 * comes back as an error payload — two routes into the UI, not one.
 */
const readFailure = (status: number): Response =>
  HttpResponse.json(
    errorBody(
      status >= 500
        ? ALERTS_LIST_SERVER_ERROR_DETAIL
        : ALERTS_READ_FORBIDDEN_DETAIL,
      status,
    ),
    { status },
  );

const collection = (data: unknown[]) => ({
  data,
  meta: {
    version: "v1",
    pagination: { page: 1, pages: 1, count: data.length },
  },
});

/** The rule read's channel shape: resolved name and privacy, no Slack call. */
const storedChannelAttribute = (channel: AlertsSlackChannelFixture) => ({
  id: channel.id,
  name: channel.name,
  is_private: channel.isPrivate,
});

interface RuleWriteAttributes {
  name?: string;
  description?: string;
  enabled?: boolean;
  trigger?: AlertRuleFixture["trigger"];
  condition?: AlertRuleFixture["condition"];
  recipient_emails?: string[];
  /** Objects carrying only `id`; name and privacy are server-derived. */
  slack_channels?: { id: string }[];
}

const parseRuleAttributes = async (
  request: Request,
): Promise<RuleWriteAttributes> => {
  const body = (await request.json().catch(() => null)) as {
    data?: { attributes?: RuleWriteAttributes };
  } | null;
  return body?.data?.attributes ?? {};
};

export const handlersForAlerts = (fx: AlertsFixture) => {
  // Mutable copies: writes must not reach through to the caller's fixture.
  const rules: AlertRuleFixture[] = fx.rules.map((rule) => ({
    ...rule,
    recipientEmails: [...rule.recipientEmails],
    slackChannelIds: [...rule.slackChannelIds],
  }));
  let createdCount = 0;

  const isConnected = fx.slackIntegration?.connected === true;

  const configuredChannel = (
    channelId: string,
  ): AlertsSlackChannelFixture | undefined =>
    fx.slackIntegration?.channels.find(
      (candidate) => candidate.id === channelId,
    );

  /**
   * What `GET /alerts/slack-channels` offers, as signed (section 6.2): only
   * the confirmed channels of the enabled and connected integration. An
   * unconfirmed one would just be an offer of a refusal.
   */
  const eligibleChannels = (): AlertsSlackChannelFixture[] =>
    isConnected
      ? (fx.slackIntegration?.channels ?? []).filter(
          (channel) => channel.confirmationSentAt !== null,
        )
      : [];

  /** Every ineligible condition answers the one signed pair (section 6.1). */
  const notEligible = (detail: string): Response =>
    HttpResponse.json(
      errorBody(detail, 400, ALERTS_SLACK_CHANNEL_NOT_ELIGIBLE_CODE),
      { status: 400 },
    );

  /**
   * The rule-write validation the contract signs: every channel a write ADDS
   * needs an enabled and connected integration, the channel configured on it,
   * and a non-null `confirmation_sent_at`. Only newly added channels are
   * validated (section 6.3), so ids the rule already stores never block an
   * edit — a same-workspace reinstall that reset their confirmations does not
   * freeze the rule. Answered before any write lands, so a refusal leaves the
   * stored rule unchanged.
   */
  const refuseInvalidChannels = (
    channelIds: string[] | undefined,
    retainedIds: readonly string[] = [],
  ): Response | null => {
    const added = (channelIds ?? []).filter(
      (channelId) => !retainedIds.includes(channelId),
    );
    if (added.length === 0) return null;

    if (!isConnected) return notEligible(ALERTS_SLACK_NOT_CONNECTED_DETAIL);

    for (const channelId of added) {
      const channel = configuredChannel(channelId);
      if (!channel) {
        return notEligible(alertsChannelNotAuthorizedDetail(channelId));
      }
      if (channel.confirmationSentAt === null) {
        return notEligible(alertsChannelNotConfirmedDetail(channelId));
      }
    }

    return null;
  };

  /** Deduplicated, as the contract requires of every Slack id list. */
  const storedIds = (written: { id: string }[]): string[] =>
    Array.from(new Set(written.map((channel) => channel.id)));

  /**
   * The read enriches the mapping's ids from the integration — the mapping
   * table holds no metadata — so a channel the workspace no longer carries is
   * simply absent, exactly as the cascade leaves it.
   */
  const ruleResource = (rule: AlertRuleFixture) => ({
    id: rule.id,
    type: "alert-rules",
    attributes: {
      name: rule.name,
      description: rule.description,
      enabled: rule.enabled,
      trigger: rule.trigger,
      condition: rule.condition,
      schema_version: 1,
      recipient_emails: rule.recipientEmails,
      slack_channels: rule.slackChannelIds.flatMap((channelId) => {
        const channel = configuredChannel(channelId);
        return channel ? [storedChannelAttribute(channel)] : [];
      }),
      inserted_at: TS,
      updated_at: TS,
    },
  });

  const integrationResource = (
    integration: NonNullable<AlertsFixture["slackIntegration"]>,
  ) => ({
    id: integration.id,
    type: "integrations",
    attributes: {
      inserted_at: TS,
      updated_at: TS,
      enabled: true,
      connected: integration.connected,
      connection_last_checked_at: integration.connected === null ? null : TS,
      integration_type: "slack",
      configuration: {
        team_id: "T01PROWLER",
        team_name: integration.workspaceName,
        bot_user_id: "U01PROWLERBOT",
        channels: integration.channels.map((channel) => ({
          ...storedChannelAttribute(channel),
          confirmation_sent_at: channel.confirmationSentAt,
        })),
        verification: {
          task_id: null,
          started_at: null,
          finished_at: integration.connected === null ? null : TS,
        },
      },
    },
    links: { self: `${API}/integrations/${integration.id}` },
  });

  return [
    // --- Rules -------------------------------------------------------------
    http.get(`${API}/alerts/rules`, () => {
      if (fx.listServerError) {
        return HttpResponse.json(
          errorBody(ALERTS_LIST_SERVER_ERROR_DETAIL, 500),
          { status: 500 },
        );
      }
      return HttpResponse.json(collection(rules.map(ruleResource)));
    }),

    /**
     * Registered before the `:id` routes so the literal paths win. The seed
     * echoes the filter bag back as a leaf condition — the UI treats the DSL
     * opaquely, so the exact translation is this fixture's business alone.
     */
    http.post(`${API}/alerts/rules/seed`, async ({ request }) => {
      const body = (await request.json().catch(() => null)) as {
        data?: { attributes?: { filter_bag?: Record<string, unknown> } };
      } | null;
      const bag = body?.data?.attributes?.filter_bag ?? {};
      const severity = bag["filter[severity__in]"];
      const severityValues = Array.isArray(severity)
        ? severity
        : typeof severity === "string"
          ? severity.split(",")
          : ["critical"];

      return HttpResponse.json({
        data: {
          id: "seeded-rule",
          type: "alert-rule-seedings",
          attributes: {
            condition: {
              op: "count_gte",
              filter: { severity: severityValues },
              value: 1,
            },
          },
        },
      });
    }),

    http.post(`${API}/alerts/rules/preview`, () =>
      HttpResponse.json({
        data: {
          id: "preview",
          type: "alert-rule-previews",
          attributes: {
            summary: { finding_count_total: 3, top_severity: "critical" },
            evaluation_failed: false,
          },
        },
      }),
    ),

    http.post(`${API}/alerts/rules`, async ({ request }) => {
      const attributes = await parseRuleAttributes(request);
      const written = storedIds(attributes.slack_channels ?? []);
      // A create retains nothing: everything supplied is newly added.
      const refusal = refuseInvalidChannels(written);
      if (refusal) return refusal;

      createdCount += 1;
      const created: AlertRuleFixture = {
        id: `created-rule-${createdCount}`,
        name: attributes.name ?? "",
        description: attributes.description ?? "",
        enabled: attributes.enabled ?? true,
        trigger: attributes.trigger ?? "after_scan",
        condition: attributes.condition ?? {},
        recipientEmails: attributes.recipient_emails ?? [],
        // Omission defaults both destination lists to empty.
        slackChannelIds: written,
      };
      rules.push(created);

      return HttpResponse.json(
        { data: ruleResource(created) },
        { status: 201 },
      );
    }),

    http.get<{ id: string }>(`${API}/alerts/rules/:id`, ({ params }) => {
      const rule = rules.find((candidate) => candidate.id === params.id);
      if (!rule) {
        return HttpResponse.json(errorBody("Not found.", 404), { status: 404 });
      }
      return HttpResponse.json({ data: ruleResource(rule) });
    }),

    http.patch<{ id: string }>(
      `${API}/alerts/rules/:id`,
      async ({ params, request }) => {
        const rule = rules.find((candidate) => candidate.id === params.id);
        if (!rule) {
          return HttpResponse.json(errorBody("Not found.", 404), {
            status: 404,
          });
        }

        const attributes = await parseRuleAttributes(request);
        const written = attributes.slack_channels
          ? storedIds(attributes.slack_channels)
          : undefined;
        // Retained ids are the rule's stored selection: never re-validated.
        const refusal = refuseInvalidChannels(written, rule.slackChannelIds);
        if (refusal) return refusal;

        if (attributes.name !== undefined) rule.name = attributes.name;
        if (attributes.description !== undefined) {
          rule.description = attributes.description;
        }
        if (attributes.enabled !== undefined) rule.enabled = attributes.enabled;
        if (attributes.trigger !== undefined) rule.trigger = attributes.trigger;
        if (attributes.condition !== undefined) {
          rule.condition = attributes.condition;
        }
        if (attributes.recipient_emails !== undefined) {
          rule.recipientEmails = attributes.recipient_emails;
        }
        // A supplied list replaces the whole Slack selection atomically, `[]`
        // clears it, and omitting the key leaves it untouched.
        if (written !== undefined) {
          rule.slackChannelIds = written;
        }

        return HttpResponse.json({ data: ruleResource(rule) });
      },
    ),

    http.delete<{ id: string }>(`${API}/alerts/rules/:id`, ({ params }) => {
      const index = rules.findIndex((candidate) => candidate.id === params.id);
      if (index === -1) {
        return HttpResponse.json(errorBody("Not found.", 404), { status: 404 });
      }
      rules.splice(index, 1);
      return new HttpResponse(null, { status: 204 });
    }),

    // --- The channels the alert form offers ---------------------------------
    http.get(`${API}/alerts/slack-channels`, () => {
      if (fx.channelsReadError) return readFailure(fx.channelsReadError);
      return HttpResponse.json({
        data: eligibleChannels().map((channel) => ({
          type: "slack-channels",
          id: channel.id,
          attributes: { name: channel.name, is_private: channel.isPrivate },
        })),
      });
    }),

    // --- Recipients ---------------------------------------------------------
    http.get(`${API}/alerts/recipients`, () =>
      HttpResponse.json(
        collection(
          fx.recipients.map((recipient, index) => ({
            id: `recipient-${index + 1}`,
            type: "alert-recipients",
            attributes: {
              email: recipient.email,
              status: recipient.status,
              inserted_at: TS,
              updated_at: TS,
            },
          })),
        ),
      ),
    ),

    // --- The integration read that tells the two empty states apart ---------
    http.get(`${API}/integrations`, ({ request }) => {
      if (fx.integrationsReadError)
        return readFailure(fx.integrationsReadError);
      const type = new URL(request.url).searchParams.get(
        "filter[integration_type]",
      );
      // An unfiltered read would pull every type into the alert form.
      const install =
        type === "slack" && fx.slackIntegration ? fx.slackIntegration : null;
      return HttpResponse.json(
        collection(install ? [integrationResource(install)] : []),
      );
    }),

    // --- Sibling reads the alerts page issues on mount -----------------------
    http.get(`${API}/providers`, () => HttpResponse.json(collection([]))),
    http.get(`${API}/scans`, () => HttpResponse.json(collection([]))),
    http.get(`${API}/findings/metadata/latest`, () =>
      HttpResponse.json({
        data: {
          id: "latest",
          type: "findings-metadata",
          attributes: {
            regions: [],
            services: [],
            resource_types: [],
            categories: [],
            groups: [],
          },
        },
      }),
    ),
  ];
};
