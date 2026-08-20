/**
 * MSW handlers for the Slack integration, derived from the signed API contract
 * in `openspec/changes/add-slack-alert-channels/contract/slack-alerts-api.md`
 * (the API itself lives in the cloud repository). State is per-call: an
 * exchange creates the install the subsequent `GET /integrations` returns, and
 * a save or a connection check writes to it.
 *
 * Wire them per test via `worker.use(...handlersForSlack(fx))`.
 */

import { http, HttpResponse } from "msw";

import {
  INTEGRATIONS_SERVER_ERROR_DETAIL,
  NO_VERIFICATION,
  PROXY_CHALLENGE_PAGE,
  SLACK_AUTHORIZE_URL,
  SLACK_DIFFERENT_WORKSPACE_DETAIL,
  SLACK_EXCHANGE_OUTCOME,
  SLACK_INTEGRATION_ID,
  SLACK_INVALID_CODE_DETAIL,
  SLACK_NO_CHANNEL_DETAIL,
  SLACK_RATE_LIMITED_REFUSAL,
  SLACK_REFUSED_STATE_DETAIL,
  SLACK_UNCONFIGURED_DETAIL,
  SLACK_UNKNOWN_CHANNEL_DETAIL,
  SLACK_UPSTREAM_DETAIL,
  SLACK_UPSTREAM_ERROR_CODE,
  SLACK_WORKSPACE_CONFLICT_CODE,
} from "./slack.fixtures";
import type {
  SlackAuthorizedChannelFixture,
  SlackExchangeOutcome,
  SlackFixture,
  SlackInstallFixture,
  SlackRefusalFixture,
} from "./slack.fixtures";

const API = process.env.UI_API_BASE_URL;
const TS = "2026-08-10T09:00:00Z";
/** When a check run by these handlers lands, and stamps its confirmations. */
const CHECK_TS = "2026-08-10T10:15:00Z";

const CONNECTION_TASK_PREFIX = "slack-conn-task-";

/** Order-insensitive: a reorder is not a changed set (contract, PATCH). */
const sameChannelIds = (a: string[], b: string[]) =>
  a.length === b.length && new Set([...a, ...b]).size === a.length;

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

/**
 * Answer a fixture's refusal as the API would: its own status, its `code`
 * when it names one, and `Retry-After` only where the status carries a wait.
 */
const refuse = (refusal: SlackRefusalFixture) =>
  HttpResponse.json(
    errorBody(refusal.detail, refusal.status, refusal.code ?? undefined),
    {
      status: refusal.status,
      ...(refusal.retryAfterSeconds === null
        ? {}
        : { headers: { "Retry-After": String(refusal.retryAfterSeconds) } }),
    },
  );

const configuration = (install: SlackInstallFixture) => {
  const verification = install.verification ?? NO_VERIFICATION;
  return {
    team_id: install.workspace.teamId,
    team_name: install.workspace.teamName,
    bot_user_id: install.workspace.botUserId,
    // Always an array: a new install carries an empty one rather than omitting
    // the key (contract, OAuth and reads).
    channels: (install.workspace.authorizedChannels ?? []).map((channel) => ({
      id: channel.id,
      name: channel.name,
      is_private: channel.isPrivate,
      confirmation_sent_at: channel.confirmationSentAt,
    })),
    verification: {
      task_id: verification.taskId,
      started_at: verification.startedAt,
      finished_at: verification.finishedAt,
    },
  };
};

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
    configuration: configuration(install),
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
 * The confirmation a check posts, applied to one channel: only where none has
 * landed yet, and stamped only once Slack accepted the post — so the channel a
 * failure names keeps none, and a retry has it left to do.
 */
const confirmedByThisRun =
  (failedChannelName: string | null) =>
  (channel: SlackAuthorizedChannelFixture): SlackAuthorizedChannelFixture =>
    channel.confirmationSentAt === null && channel.name !== failedChannelName
      ? { ...channel, confirmationSentAt: CHECK_TS }
      : channel;

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

  /** What the exchange leaves behind: no channels, nothing verified yet. */
  const freshInstall = (id?: string): SlackInstallFixture => ({
    id: id ?? SLACK_INTEGRATION_ID,
    connected: null,
    connectionLastCheckedAt: null,
    workspace: { ...fx.exchangeWorkspace, authorizedChannels: [] },
    verification: { ...NO_VERIFICATION },
  });

  const unconfigured = () =>
    HttpResponse.json(errorBody(SLACK_UNCONFIGURED_DETAIL, 503), {
      status: 503,
    });

  const rateLimited = () => refuse(SLACK_RATE_LIMITED_REFUSAL);

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
          install = freshInstall();
          return unreadableExchange(fx.exchangeOutcome);
        case SLACK_EXCHANGE_OUTCOME.REINSTALLED:
          install = {
            ...freshInstall(install?.id),
            workspace: {
              ...fx.exchangeWorkspace,
              // A same-workspace reinstall keeps the authorized channels and
              // resets every confirmation, along with the connection and
              // verification state (contract, OAuth and reads).
              authorizedChannels: (
                install?.workspace.authorizedChannels ?? []
              ).map((channel) => ({ ...channel, confirmationSentAt: null })),
            },
          };
          return HttpResponse.json({ data: integrationResource(install) });
        default:
          install = freshInstall();
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
        // The check reaches every configured channel, so the API requires at
        // least one (contract, Connection).
        if (!install?.workspace.authorizedChannels?.length) {
          return HttpResponse.json(errorBody(SLACK_NO_CHANNEL_DETAIL, 400), {
            status: 400,
          });
        }

        // The task id is pre-generated and stored before the task is
        // published; the worker is what stamps `started_at`.
        const taskId = `${CONNECTION_TASK_PREFIX}${params.id}`;
        install.verification = {
          taskId,
          startedAt: null,
          finishedAt: null,
        };

        return HttpResponse.json(taskResource(taskId, "executing", null), {
          status: 202,
        });
      },
    ),

    http.get<{ taskId: string }>(`${API}/tasks/:taskId`, ({ params }) => {
      const { connected, error, failedChannelName } = fx.connection;
      // Only a task whose id still matches may write: a late one must not
      // overwrite a newer check (contract, Connection).
      if (
        install &&
        params.taskId.startsWith(CONNECTION_TASK_PREFIX) &&
        install.verification?.taskId === params.taskId
      ) {
        install.connected = connected;
        install.connectionLastCheckedAt = CHECK_TS;
        install.verification = {
          taskId: params.taskId,
          startedAt: CHECK_TS,
          finishedAt: CHECK_TS,
        };
        install.workspace.authorizedChannels = (
          install.workspace.authorizedChannels ?? []
        ).map(confirmedByThisRun(failedChannelName ?? null));
      }
      return HttpResponse.json(
        // TODO(Josema): the key the result names a failing channel under.
        taskResource(params.taskId, "completed", {
          connected,
          error,
          channel: failedChannelName ?? null,
        }),
      );
    }),

    // --- Channels ----------------------------------------------------------
    http.get<{ id: string }>(
      `${API}/integrations/:id/slack/channels`,
      ({ params, request }) => {
        // The UI follows `links.next` opaquely, so the cursor's shape is this
        // fixture's business alone. Read first: the page decides the refusal.
        const cursor = Number(
          new URL(request.url).searchParams.get(CHANNEL_CURSOR_PARAM) ?? "0",
        );

        // An endpoint-specific refusal wins over the blanket rate limiting,
        // and applies from the named cursor, so a partial read is expressible.
        if (
          fx.channelsRefusal &&
          cursor >= (fx.channelsRefusalFromCursor ?? 0)
        ) {
          return refuse(fx.channelsRefusal);
        }
        if (fx.rateLimited) return rateLimited();

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
     * The generic PATCH. The write carries objects that name only `id`; the
     * names and privacy are derived from them here, as the API derives them
     * from Slack (contract, PATCH).
     */
    http.patch(`${API}/integrations/:id`, async ({ request }) => {
      const body = (await request.json().catch(() => null)) as {
        data?: { attributes?: Record<string, unknown> };
      } | null;
      const attributes = body?.data?.attributes ?? {};
      const configurationPatch = attributes.configuration as
        | { channels?: { id: string }[] }
        | undefined;
      const requested = configurationPatch?.channels;

      if (!install) {
        return HttpResponse.json(errorBody("Not found.", 404), { status: 404 });
      }
      // The API's write serializer names the attributes it will not take and
      // refuses the whole save, rather than quietly dropping the extra one:
      // sending `integration_type` here refused every channel save.
      const refusedAttributes = Object.keys(attributes).filter(
        (attribute) => attribute !== "configuration",
      );
      if (refusedAttributes.length > 0) {
        const named = refusedAttributes
          .map((attribute) => `'${attribute}'`)
          .join(", ");
        return HttpResponse.json(errorBody(`Invalid fields: {${named}}`, 400), {
          status: 400,
        });
      }
      // An omitted list leaves the set alone; an empty one clears it. Nothing
      // to validate against Slack either, so no refusal is reachable here.
      if (requested === undefined) {
        return HttpResponse.json({ data: integrationResource(install) });
      }

      // Deduplicated before anything is validated or saved.
      const channelIds = Array.from(
        new Set(requested.map((channel) => channel.id)),
      );
      const matched = channelIds
        .map((channelId) =>
          fx.channels.find((channel) => channel.id === channelId),
        )
        .filter((channel) => channel !== undefined);

      // Checked before the id lookup: the picker did offer these channels, and
      // Slack refused one anyway when the API validated the set.
      if (fx.channelSaveRefusal) return refuse(fx.channelSaveRefusal);
      // One unknown id refuses the whole save: the set is validated together.
      if (matched.length !== channelIds.length) {
        return HttpResponse.json(errorBody(SLACK_UNKNOWN_CHANNEL_DETAIL, 400), {
          status: 400,
        });
      }

      const previous = install.workspace.authorizedChannels ?? [];
      const confirmedAt = new Map(
        previous.map((channel) => [channel.id, channel.confirmationSentAt]),
      );
      install.workspace.authorizedChannels = matched.map((channel) => ({
        ...channel,
        // Retained ids keep their confirmation; new ones start without one.
        confirmationSentAt: confirmedAt.get(channel.id) ?? null,
      }));

      // A changed id set resets the connection and verification state, so the
      // record never claims a check covered a channel it never saw. Reordering
      // the same ids changes nothing.
      if (
        !sameChannelIds(
          previous.map((channel) => channel.id),
          channelIds,
        )
      ) {
        install.connected = null;
        install.connectionLastCheckedAt = null;
        install.verification = { ...NO_VERIFICATION };
      }

      return HttpResponse.json({ data: integrationResource(install) });
    }),

    // Disconnect. Revocation at Slack is best-effort: the row is removed either
    // way and the outcome travels in `meta` — or nowhere at all, in the plain
    // `204` a deployment with no `destroy` override sends.
    http.delete<{ id: string }>(`${API}/integrations/:id`, ({ params }) => {
      if (!install || install.id !== params.id) {
        return HttpResponse.json(errorBody("Not found.", 404), { status: 404 });
      }
      // Checked first: a refused disconnect removes nothing.
      if (fx.disconnectRefusal) return refuse(fx.disconnectRefusal);

      install = null;
      if (fx.revocation.revoked === null) {
        return new HttpResponse(null, { status: 204 });
      }
      return HttpResponse.json({ meta: { revoked: fx.revocation.revoked } });
    }),
  ];
};
