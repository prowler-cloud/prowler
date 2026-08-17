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
  INTEGRATIONS_SERVER_ERROR_DETAIL,
  PROXY_CHALLENGE_PAGE,
  SLACK_AUTHORIZE_URL,
  SLACK_DIFFERENT_WORKSPACE_DETAIL,
  SLACK_EXCHANGE_OUTCOME,
  SLACK_INTEGRATION_ID,
  SLACK_INVALID_CODE_DETAIL,
  SLACK_NO_CHANNEL_DETAIL,
  SLACK_RATE_LIMITED_DETAIL,
  SLACK_REFUSED_STATE_DETAIL,
  SLACK_RETRY_AFTER_SECONDS,
  SLACK_UNCONFIGURED_DETAIL,
  SLACK_UPSTREAM_DETAIL,
  SLACK_UPSTREAM_ERROR_CODE,
  SLACK_WORKSPACE_CONFLICT_CODE,
} from "./slack.fixtures";
import type {
  SlackExchangeOutcome,
  SlackFixture,
  SlackInstallFixture,
} from "./slack.fixtures";

const API = process.env.UI_API_BASE_URL;
const TS = "2026-08-10T09:00:00Z";

const CONNECTION_TASK_PREFIX = "slack-conn-task-";

/**
 * A JSON:API error as the Slack endpoints raise it.
 *
 * `code` is the machine-readable reason the UI maps; `detail` is human copy.
 * `status` is a string, per the spec. `source.pointer` is `/data` even when the
 * API raised a field-shaped `ValidationError` — the errors are about the
 * request, not about one attribute of it.
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

const configuration = (workspace: SlackInstallFixture["workspace"]) => ({
  team_id: workspace.teamId,
  team_name: workspace.teamName,
  bot_user_id: workspace.botUserId,
  // Absent until a channel is chosen — the API omits the keys rather than
  // serializing nulls, so a consumer that reads `null` as "not chosen" would
  // be reading a value that never arrives.
  ...(workspace.channelId ? { channel_id: workspace.channelId } : {}),
  ...(workspace.channelName ? { channel_name: workspace.channelName } : {}),
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
    // The configuration carries server-owned keys the UI does not send.
    configuration: configuration(install.workspace),
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

/**
 * A completion the API accepted and the UI cannot read back.
 *
 * All three are `2xx`, so `response.ok` is true and none of them travels the
 * refusal path: the first two make `response.json()` throw, the third parses
 * into a body that names no resource.
 */
const unreadableExchange = (outcome: SlackExchangeOutcome): Response => {
  switch (outcome) {
    case SLACK_EXCHANGE_OUTCOME.UNREADABLE_NO_CONTENT:
      return new HttpResponse(null, { status: 204 });
    case SLACK_EXCHANGE_OUTCOME.UNREADABLE_HTML:
      return HttpResponse.html(PROXY_CHALLENGE_PAGE);
    default:
      return HttpResponse.json({ meta: { version: "v1" } });
  }
};

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

  /**
   * Slack's own rate limit, surfaced as a `429` carrying `Retry-After`. It is
   * neither a refusal the user can act on nor "no Slack app here", so it names
   * no `code`: the status is the whole reason.
   */
  const rateLimited = () =>
    HttpResponse.json(errorBody(SLACK_RATE_LIMITED_DETAIL, 429), {
      status: 429,
      headers: { "Retry-After": String(SLACK_RETRY_AFTER_SECONDS) },
    });

  /**
   * Slack's own side broken, behind a deployment that is configured correctly.
   * A `502`, per the contract's taxonomy — a server fault rather than a Slack
   * state, which is the one refusal here the UI reports as well as describes.
   */
  const upstreamError = () =>
    HttpResponse.json(
      errorBody(SLACK_UPSTREAM_DETAIL, 502, SLACK_UPSTREAM_ERROR_CODE),
      { status: 502, statusText: "Bad Gateway" },
    );

  return [
    // --- OAuth ------------------------------------------------------------
    http.post(`${API}/integrations/slack/oauth/authorize-url`, () => {
      if (!fx.appConfigured) return unconfigured();
      if (fx.rateLimited) return rateLimited();
      if (fx.oauthUpstreamError) return upstreamError();
      // A proxy answering in place of the API: a `200` the UI reads as success
      // and then finds nothing in.
      if (fx.authorizeUrlUnreadable) {
        return HttpResponse.html(PROXY_CHALLENGE_PAGE);
      }
      // The URL travels in `meta`; the call creates nothing.
      return HttpResponse.json({
        meta: { authorize_url: SLACK_AUTHORIZE_URL },
      });
    }),

    http.post(`${API}/integrations/slack/oauth/exchange`, () => {
      if (!fx.appConfigured) return unconfigured();
      if (fx.rateLimited) return rateLimited();
      if (fx.oauthUpstreamError) return upstreamError();

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
          // A conflict with what the tenant already has, not a bad request:
          // `409`, named by its `code` so the UI can say which conflict it is.
          return HttpResponse.json(
            errorBody(
              SLACK_DIFFERENT_WORKSPACE_DETAIL,
              409,
              SLACK_WORKSPACE_CONFLICT_CODE,
            ),
            { status: 409 },
          );
        case SLACK_EXCHANGE_OUTCOME.UNREADABLE_NO_CONTENT:
        case SLACK_EXCHANGE_OUTCOME.UNREADABLE_HTML:
        case SLACK_EXCHANGE_OUTCOME.UNREADABLE_NO_DATA:
          // The install still happened: the API upserts the integration before
          // it answers, so a subsequent read finds the workspace connected even
          // though the answer that announced it was unreadable.
          install = {
            id: SLACK_INTEGRATION_ID,
            connected: null,
            connectionLastCheckedAt: null,
            workspace: { ...fx.exchangeWorkspace },
          };
          return unreadableExchange(fx.exchangeOutcome);
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
      // The shared read failing on the API's own side, which is a different
      // answer from every Slack refusal above: no `code` names it, and the
      // status is all the UI has to go on.
      if (fx.listServerError) {
        return HttpResponse.json(
          errorBody(INTEGRATIONS_SERVER_ERROR_DETAIL, 500),
          { status: 500 },
        );
      }

      const type = new URL(request.url).searchParams.get(
        "filter[integration_type]",
      );
      // An unfiltered read would pull every integration type into the Slack
      // page, so serve the install only for the filter it actually sends.
      return HttpResponse.json(collection(type === "slack" ? install : null));
    }),

    http.post<{ id: string }>(
      `${API}/integrations/:id/connection`,
      ({ params }) => {
        // The check posts to the integration's channel, so there is nothing to
        // check until one is recorded: the API refuses rather than reporting a
        // connection it never tested.
        if (!install?.workspace.channelId) {
          return HttpResponse.json(errorBody(SLACK_NO_CHANNEL_DETAIL, 400), {
            status: 400,
          });
        }

        return HttpResponse.json(
          taskResource(
            `${CONNECTION_TASK_PREFIX}${params.id}`,
            "executing",
            null,
          ),
          { status: 202 },
        );
      },
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
