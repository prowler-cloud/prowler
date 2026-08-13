/**
 * MSW handlers for the Slack integration, derived from the API contract in
 * `openspec/changes/add-slack-integration/design.md` (the API itself lives in
 * the cloud repository). State is per-call: an exchange creates the install the
 * subsequent `GET /integrations` returns.
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
  SLACK_NO_DEFAULT_CHANNEL_DETAIL,
  SLACK_RATE_LIMITED_DETAIL,
  SLACK_REFUSED_STATE_DETAIL,
  SLACK_RETRY_AFTER_SECONDS,
  SLACK_UNCONFIGURED_DETAIL,
  SLACK_UNKNOWN_CHANNEL_DETAIL,
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
const TEST_MESSAGE_TASK_PREFIX = "slack-test-message-task-";

/** Opaque to the UI, which only ever follows `links.next` (design D6). */
const CHANNEL_CURSOR_PARAM = "page[cursor]";

/**
 * `status` is a string, per the JSON:API spec. `source.pointer` is `/data` even
 * for a field-shaped `ValidationError`: the errors are about the request.
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
  // The API omits these keys until a channel is chosen, never sending nulls.
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
 * All three are `2xx`: the first two make `response.json()` throw, the third
 * parses into a body that names no resource.
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
  // Mutable copy: the exchange must not write through to the caller's fixture.
  let install: SlackInstallFixture | null = fx.install
    ? { ...fx.install, workspace: { ...fx.install.workspace } }
    : null;

  const unconfigured = () =>
    HttpResponse.json(errorBody(SLACK_UNCONFIGURED_DETAIL, 503), {
      status: 503,
    });

  const rateLimited = () =>
    HttpResponse.json(errorBody(SLACK_RATE_LIMITED_DETAIL, 429), {
      status: 429,
      headers: { "Retry-After": String(SLACK_RETRY_AFTER_SECONDS) },
    });

  /** A `502` per the contract's taxonomy: a server fault, not a Slack state. */
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
          // The install still happened: the API upserts before it answers.
          install = {
            id: SLACK_INTEGRATION_ID,
            connected: null,
            connectionLastCheckedAt: null,
            workspace: { ...fx.exchangeWorkspace },
          };
          return unreadableExchange(fx.exchangeOutcome);
        case SLACK_EXCHANGE_OUTCOME.REINSTALLED:
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
      if (fx.listServerError) {
        return HttpResponse.json(
          errorBody(INTEGRATIONS_SERVER_ERROR_DETAIL, 500),
          { status: 500 },
        );
      }

      const type = new URL(request.url).searchParams.get(
        "filter[integration_type]",
      );
      // An unfiltered read would pull every type into the Slack page.
      return HttpResponse.json(collection(type === "slack" ? install : null));
    }),

    http.post<{ id: string }>(
      `${API}/integrations/:id/connection`,
      ({ params }) => {
        // The check posts to the channel, so the API refuses until one exists.
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
      // The test message settles as its own task (design D9), reporting only
      // whether Slack accepted the post.
      if (params.taskId.startsWith(TEST_MESSAGE_TASK_PREFIX)) {
        const { accepted, error } = fx.testMessage;
        return HttpResponse.json(
          taskResource(params.taskId, accepted ? "completed" : "failed", {
            error,
          }),
        );
      }

      const { connected, error } = fx.connection;
      if (install && params.taskId.startsWith(CONNECTION_TASK_PREFIX)) {
        install.connected = connected;
        install.connectionLastCheckedAt = TS;
      }
      return HttpResponse.json(
        taskResource(params.taskId, "completed", { connected, error }),
      );
    }),

    // --- Channels ----------------------------------------------------------
    http.get<{ id: string }>(
      `${API}/integrations/:id/slack/channels`,
      ({ params, request }) => {
        if (fx.channelsError) {
          return HttpResponse.json(errorBody(fx.channelsError, 400), {
            status: 400,
          });
        }

        // Cursor pagination: the UI follows `links.next` opaquely, so the
        // cursor's shape is this fixture's business alone.
        const cursor = Number(
          new URL(request.url).searchParams.get(CHANNEL_CURSOR_PARAM) ?? "0",
        );
        const nextCursor = cursor + fx.channelsPageSize;
        const page = fx.channels.slice(cursor, nextCursor);
        const hasMore = nextCursor < fx.channels.length;

        return HttpResponse.json({
          data: page.map((channel) => ({
            type: "slack-channels",
            id: channel.id,
            attributes: { name: channel.name, is_private: channel.isPrivate },
          })),
          links: {
            next: hasMore
              ? `${API}/integrations/${params.id}/slack/channels` +
                `?${CHANNEL_CURSOR_PARAM}=${nextCursor}`
              : null,
          },
        });
      },
    ),

    /**
     * The generic PATCH, recording the default channel. The UI submits only
     * `channel_id`; the name here is derived from the channel the id resolves
     * to, exactly as the API derives it from Slack (design D6).
     */
    http.patch(`${API}/integrations/:id`, async ({ request }) => {
      const body = (await request.json().catch(() => null)) as {
        data?: { attributes?: { configuration?: { channel_id?: string } } };
      } | null;
      const channelId = body?.data?.attributes?.configuration?.channel_id;
      const channel = fx.channels.find((c) => c.id === channelId);

      if (!install) {
        return HttpResponse.json(errorBody("Not found.", 404), { status: 404 });
      }
      if (!channel) {
        return HttpResponse.json(errorBody(SLACK_UNKNOWN_CHANNEL_DETAIL, 400), {
          status: 400,
        });
      }

      install.workspace.channelId = channel.id;
      install.workspace.channelName = channel.name;
      return HttpResponse.json({ data: integrationResource(install) });
    }),

    // --- Test message ------------------------------------------------------
    http.post<{ id: string }>(
      `${API}/integrations/:id/slack/test-message`,
      ({ params }) => {
        if (!install?.workspace.channelId) {
          return HttpResponse.json(
            errorBody(SLACK_NO_DEFAULT_CHANNEL_DETAIL, 400),
            { status: 400 },
          );
        }
        return HttpResponse.json(
          taskResource(
            `${TEST_MESSAGE_TASK_PREFIX}${params.id}`,
            "available",
            null,
          ),
          { status: 202 },
        );
      },
    ),
  ];
};
