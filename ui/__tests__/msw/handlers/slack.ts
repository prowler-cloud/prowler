/**
 * MSW handlers for the Slack integration, derived from the API contract in
 * `openspec/changes/add-slack-integration/design.md`.
 *
 * The Slack API is implemented in the cloud repository, so these handlers are
 * the UI lane's only view of it: they are what the browser-mode tests run
 * against, and drift between them and the deployed backend is a contract
 * conversation, not a local fix.
 *
 * State is per-call: an exchange really does create the install the subsequent
 * `GET /integrations` returns, so a test can drive connect → read without
 * hand-seeding the result.
 *
 * Wire them per test via `worker.use(...handlersForSlack(fx))`.
 */

import { http, HttpResponse } from "msw";

import {
  SLACK_AUTHORIZE_URL,
  SLACK_DIFFERENT_WORKSPACE_DETAIL,
  SLACK_EXCHANGE_OUTCOME,
  SLACK_INTEGRATION_ID,
  SLACK_INVALID_CODE_DETAIL,
  SLACK_REFUSED_STATE_DETAIL,
  SLACK_UNCONFIGURED_DETAIL,
} from "./slack.fixtures";
import type { SlackFixture, SlackInstallFixture } from "./slack.fixtures";

const API = process.env.UI_API_BASE_URL;
const TS = "2026-08-10T09:00:00Z";

const CONNECTION_TASK_PREFIX = "slack-conn-task-";

const errorBody = (detail: string, status: number) => ({
  errors: [{ detail, status: String(status) }],
});

const integrationResource = (install: SlackInstallFixture) => ({
  id: install.id,
  type: "integrations",
  attributes: {
    inserted_at: TS,
    updated_at: TS,
    enabled: true,
    connected: install.connected,
    connection_last_checked_at: install.connectionLastCheckedAt,
    integration_type: "slack",
    // No credentials: the bot token is encrypted at rest and never serialized.
    configuration: {
      team_id: install.workspace.teamId,
      team_name: install.workspace.teamName,
      channel_id: install.workspace.channelId,
      channel_name: install.workspace.channelName,
    },
  },
  links: { self: `${API}/integrations/${install.id}` },
});

const collection = (install: SlackInstallFixture | null) => ({
  data: install ? [integrationResource(install)] : [],
  meta: {
    version: "v1",
    pagination: {
      page: 1,
      pages: 1,
      count: install ? 1 : 0,
    },
  },
});

const taskResource = (id: string, state: string, result: unknown) => ({
  data: { id, type: "tasks", attributes: { state, result } },
});

export const handlersForSlack = (fx: SlackFixture) => {
  // Mutable working copy: the exchange creates or updates the install the
  // integration reads see afterwards.
  let install: SlackInstallFixture | null = fx.install
    ? { ...fx.install, workspace: { ...fx.install.workspace } }
    : null;

  const unconfigured = () =>
    HttpResponse.json(errorBody(SLACK_UNCONFIGURED_DETAIL, 503), {
      status: 503,
    });

  return [
    // --- OAuth ------------------------------------------------------------
    http.post(`${API}/integrations/slack/oauth/authorize-url`, () => {
      if (!fx.appConfigured) return unconfigured();
      // The URL travels in `meta`; the call creates nothing.
      return HttpResponse.json({
        meta: { authorize_url: SLACK_AUTHORIZE_URL },
      });
    }),

    http.post(`${API}/integrations/slack/oauth/exchange`, () => {
      if (!fx.appConfigured) return unconfigured();

      switch (fx.exchangeOutcome) {
        case SLACK_EXCHANGE_OUTCOME.REFUSED_STATE:
          return HttpResponse.json(errorBody(SLACK_REFUSED_STATE_DETAIL, 400), {
            status: 400,
          });
        case SLACK_EXCHANGE_OUTCOME.SLACK_REFUSED:
          return HttpResponse.json(errorBody(SLACK_INVALID_CODE_DETAIL, 400), {
            status: 400,
          });
        case SLACK_EXCHANGE_OUTCOME.DIFFERENT_WORKSPACE:
          return HttpResponse.json(
            errorBody(SLACK_DIFFERENT_WORKSPACE_DETAIL, 400),
            { status: 400 },
          );
        case SLACK_EXCHANGE_OUTCOME.REINSTALLED:
          // Same workspace: the credential is replaced on the row that exists,
          // so the tenant still holds exactly one Slack integration.
          install = {
            id: install?.id ?? SLACK_INTEGRATION_ID,
            connected: null,
            connectionLastCheckedAt: null,
            workspace: { ...fx.exchangeWorkspace },
          };
          return HttpResponse.json({ data: integrationResource(install) });
        default:
          install = {
            id: SLACK_INTEGRATION_ID,
            connected: null,
            connectionLastCheckedAt: null,
            workspace: { ...fx.exchangeWorkspace },
          };
          return HttpResponse.json(
            { data: integrationResource(install) },
            { status: 201 },
          );
      }
    }),

    // --- Generic integration endpoints the Slack UI reuses -----------------
    http.get(`${API}/integrations`, ({ request }) => {
      const type = new URL(request.url).searchParams.get(
        "filter[integration_type]",
      );
      // An unfiltered read would pull every integration type into the Slack
      // page, so serve the install only for the filter it actually sends.
      return HttpResponse.json(collection(type === "slack" ? install : null));
    }),

    http.post<{ id: string }>(
      `${API}/integrations/:id/connection`,
      ({ params }) =>
        HttpResponse.json(
          taskResource(
            `${CONNECTION_TASK_PREFIX}${params.id}`,
            "executing",
            null,
          ),
          { status: 202 },
        ),
    ),

    http.get<{ taskId: string }>(`${API}/tasks/:taskId`, ({ params }) => {
      const { connected, error } = fx.connection;
      if (install && params.taskId.startsWith(CONNECTION_TASK_PREFIX)) {
        install.connected = connected;
        install.connectionLastCheckedAt = TS;
      }
      return HttpResponse.json(
        taskResource(params.taskId, "completed", { connected, error }),
      );
    }),
  ];
};
