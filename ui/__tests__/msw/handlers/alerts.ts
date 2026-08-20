/**
 * MSW handlers for the alerts pages: rules CRUD, recipients, the Slack
 * integration read the channel field depends on, and the sibling reads the
 * alerts page issues on mount (providers, scans, findings metadata).
 *
 * The Slack-channel wire names are D3 working assumptions
 * (`openspec/changes/add-slack-alert-channels/design.md`) — each carries a
 * `TODO(Josema)` until the contract is signed off; a rename lands here and in
 * the adapter only.
 *
 * State is per-call: a create is visible to the next rules read. Wire them
 * per test via `worker.use(...handlersForAlerts(fx))`.
 */

import { http, HttpResponse } from "msw";

import {
  ALERTS_CHANNEL_NOT_AUTHORIZED_CODE,
  ALERTS_LIST_SERVER_ERROR_DETAIL,
  ALERTS_SLACK_NOT_CONNECTED_CODE,
  ALERTS_SLACK_NOT_CONNECTED_DETAIL,
  alertsChannelNotAuthorizedDetail,
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

const channelAttribute = (channel: AlertsSlackChannelFixture) => ({
  id: channel.id,
  name: channel.name,
  is_private: channel.isPrivate,
});

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
    // TODO(Josema): `slack_channels` read shape pending contract sign-off (D3).
    slack_channels: rule.slackChannels.map(channelAttribute),
    inserted_at: TS,
    updated_at: TS,
  },
});

const collection = (data: unknown[]) => ({
  data,
  meta: {
    version: "v1",
    pagination: { page: 1, pages: 1, count: data.length },
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
    connected: true,
    connection_last_checked_at: TS,
    integration_type: "slack",
    configuration: {
      team_id: "T01PROWLER",
      team_name: integration.workspaceName,
      bot_user_id: "U01PROWLERBOT",
      // TODO(Josema): plural stored shape pending contract sign-off (D3) —
      // supersedes the singular `channel_id` / `channel_name`.
      channels: integration.authorizedChannels.map(channelAttribute),
    },
  },
  links: { self: `${API}/integrations/${integration.id}` },
});

interface RuleWriteAttributes {
  name?: string;
  description?: string;
  enabled?: boolean;
  trigger?: AlertRuleFixture["trigger"];
  condition?: AlertRuleFixture["condition"];
  recipient_emails?: string[];
  // TODO(Josema): `slack_channels` write attribute pending contract sign-off (D3).
  slack_channels?: string[];
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
    slackChannels: rule.slackChannels.map((channel) => ({ ...channel })),
  }));
  let createdCount = 0;

  /**
   * The rule-write validation the contract promises: channels only while a
   * workspace is connected, and each within the authorized set. Answered
   * before any write lands, so a refusal leaves the stored rule unchanged.
   */
  const refuseInvalidChannels = (
    channelIds: string[] | undefined,
  ): Response | null => {
    if (!channelIds || channelIds.length === 0) return null;

    if (!fx.slackIntegration) {
      return HttpResponse.json(
        errorBody(
          ALERTS_SLACK_NOT_CONNECTED_DETAIL,
          400,
          ALERTS_SLACK_NOT_CONNECTED_CODE,
        ),
        { status: 400 },
      );
    }

    const authorized = new Set(
      fx.slackIntegration.authorizedChannels.map((channel) => channel.id),
    );
    const outside = channelIds.find((id) => !authorized.has(id));
    if (outside) {
      return HttpResponse.json(
        errorBody(
          alertsChannelNotAuthorizedDetail(outside),
          400,
          ALERTS_CHANNEL_NOT_AUTHORIZED_CODE,
        ),
        { status: 400 },
      );
    }

    return null;
  };

  /** Total by construction: ids were validated against the same set. */
  const resolveChannels = (channelIds: string[]): AlertsSlackChannelFixture[] =>
    channelIds.flatMap((id) => {
      const channel = fx.slackIntegration?.authorizedChannels.find(
        (candidate) => candidate.id === id,
      );
      return channel ? [{ ...channel }] : [];
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
      const refusal = refuseInvalidChannels(attributes.slack_channels);
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
        slackChannels: resolveChannels(attributes.slack_channels ?? []),
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
        const refusal = refuseInvalidChannels(attributes.slack_channels);
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
        // Replace-not-additive, like `recipient_emails`; omitting the key
        // leaves the stored channels — stale ones included — untouched.
        if (attributes.slack_channels !== undefined) {
          rule.slackChannels = resolveChannels(attributes.slack_channels);
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

    // --- The Slack integration the channel field reads ----------------------
    http.get(`${API}/integrations`, ({ request }) => {
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
