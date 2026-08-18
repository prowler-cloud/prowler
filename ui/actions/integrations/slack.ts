"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { pollTaskUntilSettled } from "@/actions/task/poll";
import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";
import {
  readSlackFailure,
  SLACK_GENERIC_ERROR_MESSAGE,
  SLACK_PARTIAL_CHANNEL_LIST_MESSAGE,
  SLACK_REASON_TOKEN,
  SLACK_UNREADABLE_RESULT_MESSAGE,
  slackErrorMessage,
  slackRateLimitMessage,
  slackUnknownReasonMessage,
} from "@/lib/integrations/slack-errors";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import {
  INTEGRATION_TYPE,
  type IntegrationProps,
  type SlackChannelOption,
} from "@/types/integrations";

interface SlackUnavailable {
  unavailable: true;
}

interface SlackRateLimited {
  rateLimited: true;
  retryAfterSeconds: number | null;
  message: string;
}

/**
 * The API accepted the exchange (`2xx`) and the UI could not read the workspace
 * back: the install happened, only its result is unknown.
 */
interface SlackUnconfirmed {
  unconfirmed: true;
  message: string;
}

interface SlackActionError {
  error: string;
}

interface SlackAuthorizeUrl {
  authorizeUrl: string;
}

export type SlackAuthorizeUrlResult =
  | SlackAuthorizeUrl
  | SlackUnavailable
  | SlackRateLimited
  | SlackActionError;

interface SlackExchangeInput {
  code: string;
  state: string;
}

const slackExchangeInputSchema = z.object({
  code: z.string().min(1),
  state: z.string().min(1),
});

/**
 * SSRF guard: the integration id is interpolated into the request URL, so only
 * the shape the API's ids have reaches it.
 */
const integrationIdSchema = z.uuid();

const parseIntegrationId = (integrationId: string): string | null => {
  const parsed = integrationIdSchema.safeParse(integrationId);
  return parsed.success ? parsed.data : null;
};

interface SlackExchangeSuccess {
  integration: IntegrationProps;
}

export type SlackExchangeResult =
  | SlackExchangeSuccess
  | SlackUnavailable
  | SlackRateLimited
  | SlackUnconfirmed
  | SlackActionError;

/**
 * `503`: no Slack app configured in this deployment. `404`: no Slack API at
 * all. Both mean "not available here", unlike `429`/`502` which mean "not now".
 */
const isUnavailableStatus = (status: number): boolean =>
  status === 503 || status === 404;

const RATE_LIMITED_STATUS = 429;

const SLACK_AUTHORIZE_HOSTNAME = "slack.com";
const SLACK_AUTHORIZE_PATHNAME = "/oauth/v2/authorize";
const NO_AUTHORIZE_URL_MESSAGE = "Slack did not return an authorization URL.";

/**
 * The URL is rendered as the `Add to Slack` link's `href`, so anything that is
 * not Slack's consent screen is a redirect to an origin the user did not choose.
 */
const isSlackAuthorizeUrl = (value: string): boolean => {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.hostname === SLACK_AUTHORIZE_HOSTNAME &&
      url.pathname === SLACK_AUTHORIZE_PATHNAME
    );
  } catch {
    return false;
  }
};

const INTEGRATIONS_RESOURCE_TYPE = "integrations";

/**
 * The callback names the workspace and redirects on this value alone, so a `2xx`
 * payload that is not a JSON:API resource (`{}`, `[]`, `"invalid"`) must read as
 * unreadable rather than as a connected workspace. Identity too: a resource
 * that is not a linkable Slack integration would be shown as the workspace
 * just installed.
 */
const isIntegrationResource = (value: unknown): boolean => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }

  const { id, type, attributes } = value as Record<string, unknown>;

  if (
    typeof id !== "string" ||
    id === "" ||
    type !== INTEGRATIONS_RESOURCE_TYPE ||
    typeof attributes !== "object" ||
    attributes === null ||
    Array.isArray(attributes)
  ) {
    return false;
  }

  return (
    (attributes as Record<string, unknown>).integration_type ===
    INTEGRATION_TYPE.SLACK
  );
};

const failureFrom = async (
  response: Response,
  fallback: string,
): Promise<SlackUnavailable | SlackRateLimited | SlackActionError> => {
  if (isUnavailableStatus(response.status)) return { unavailable: true };

  // A 5xx (including the `502` the contract reserves for "Slack upstream
  // broke") goes through the repo's 5xx handling, which reports to Sentry and
  // throws, so the caller's catch answers the user. Must run before
  // `readSlackFailure`: a body can only be read once.
  if (response.status >= 500) await handleApiResponse(response);

  const failure = await readSlackFailure(response);

  if (failure.status === RATE_LIMITED_STATUS) {
    return {
      rateLimited: true,
      retryAfterSeconds: failure.retryAfterSeconds,
      message: slackRateLimitMessage(failure.retryAfterSeconds),
    };
  }

  return { error: slackErrorMessage(failure, fallback) };
};

/**
 * `failureFrom` flattened to one line of copy, for the calls whose only
 * outcome is "it did not work". Rate limiting keeps its own wording:
 * `conversations.list` is Slack tier 2, so a `429` shows up here (contract,
 * Errors) and the wait it names is the useful part.
 */
const errorMessageFrom = async (
  response: Response,
  fallback: string,
): Promise<string> => {
  // Same 5xx handling as `failureFrom`, `503` excepted: here too it means Slack
  // is unavailable. Must run before `readSlackFailure`: a body can only be read
  // once.
  if (response.status >= 500 && response.status !== 503) {
    await handleApiResponse(response);
  }

  const failure = await readSlackFailure(response);

  return failure.status === RATE_LIMITED_STATUS
    ? slackRateLimitMessage(failure.retryAfterSeconds)
    : slackErrorMessage(failure, fallback);
};

/** Mint an OAuth state and get the consent URL. Creates no integration. */
export const getSlackAuthorizeUrl =
  async (): Promise<SlackAuthorizeUrlResult> => {
    const headers = await getAuthHeaders({ contentType: true });
    const url = new URL(`${apiBaseUrl}/integrations/slack/oauth/authorize-url`);

    try {
      const response = await fetch(url.toString(), { method: "POST", headers });

      if (!response.ok) {
        // Awaited inside the `try`: a returned promise's rejection would skip
        // this `catch`, and a 5xx rejects.
        return await failureFrom(
          response,
          `Unable to start the Slack install: ${response.statusText}`,
        );
      }

      // The URL travels in JSON:API `meta`: the call creates no resource. A
      // non-JSON `2xx` reads as "no URL" instead of throwing a parser message
      // the user would be shown verbatim.
      const body = await response.json().catch(() => null);
      const authorizeUrl = body?.meta?.authorize_url;

      // A URL that is not Slack's own is no more usable than a missing one.
      if (
        typeof authorizeUrl !== "string" ||
        !isSlackAuthorizeUrl(authorizeUrl)
      ) {
        return { error: NO_AUTHORIZE_URL_MESSAGE };
      }

      return { authorizeUrl };
    } catch (error) {
      return handleApiError(error);
    }
  };

/**
 * Complete the install with what Slack put in the callback URL. The API
 * consumes the `state`, exchanges the single-use `code`, and upserts the
 * tenant's Slack integration.
 */
export const exchangeSlackOAuthCode = async (
  input: SlackExchangeInput,
): Promise<SlackExchangeResult> => {
  const parsed = slackExchangeInputSchema.safeParse(input);
  if (!parsed.success) return { error: SLACK_GENERIC_ERROR_MESSAGE };

  const { code, state } = parsed.data;
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/slack/oauth/exchange`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "slack-oauth-exchanges",
          attributes: { code, state },
        },
      }),
    });

    if (!response.ok) {
      // Awaited inside the `try`: unawaited, a 5xx's rejection would skip this
      // `catch` and leave the callback on its spinner.
      return await failureFrom(
        response,
        `Unable to connect the Slack workspace: ${response.statusText}`,
      );
    }

    const body = await response.json().catch(() => null);

    // Before the guard and on both paths: the API upserted the integration
    // before answering, so a cache filled when there was none would list the
    // connected workspace as missing.
    revalidatePath("/integrations");
    revalidatePath("/integrations/slack");

    if (!isIntegrationResource(body?.data)) {
      return { unconfirmed: true, message: SLACK_UNREADABLE_RESULT_MESSAGE };
    }

    return { integration: parseStringify(body.data) as IntegrationProps };
  } catch (error) {
    return handleApiError(error);
  }
};

interface SlackChannelsSuccess {
  channels: SlackChannelOption[];
  /**
   * Present when these channels are only part of the workspace's, carrying the
   * sentence that says why: a partial read is a success, so the caller renders
   * the picker *and* the reason.
   */
  incomplete?: string;
}

export type SlackChannelsResult = SlackChannelsSuccess | SlackActionError;

/**
 * Cursor pages followed before giving up: `conversations.list` is a tier-2,
 * rate-limited Slack call (design.md, Risks), so the aggregation is bounded
 * rather than open-ended.
 */
const MAX_CHANNEL_PAGES = 20;

/**
 * Every channel Prowler can post to in the connected workspace — the picker's
 * options.
 *
 * The durable primitive, not the channel stored on the integration (design D6):
 * a consumer needing a per-rule channel reads the same endpoint. `links.next`
 * is followed opaquely — the contract does not pin the cursor parameter naming,
 * so the UI never builds one of its own. An early stop that still read
 * something reports through `incomplete`, not as a failure.
 */
export const getSlackChannels = async (
  integrationId: string,
): Promise<SlackChannelsResult> => {
  const id = parseIntegrationId(integrationId);
  if (!id) return { error: SLACK_GENERIC_ERROR_MESSAGE };

  const headers = await getAuthHeaders({ contentType: false });
  const channels: SlackChannelOption[] = [];

  const listing = new URL(`${apiBaseUrl}/integrations/${id}/slack/channels`);
  let next: string | null = listing.toString();
  let incomplete: string | null = null;

  try {
    for (let page = 0; next && page < MAX_CHANNEL_PAGES; page += 1) {
      const current: string = next;
      const response: Response = await fetch(current, {
        method: "GET",
        headers,
      });

      if (!response.ok) {
        const message = await errorMessageFrom(
          response,
          `Unable to read the workspace's channels: ${response.statusText}`,
        );

        return channels.length > 0
          ? { channels, incomplete: message }
          : { error: message };
      }

      // A page that is not JSON reads as no channels, rather than throwing a
      // parser message the user would be shown verbatim.
      const body = await response.json().catch(() => null);

      for (const resource of body?.data ?? []) {
        channels.push({
          id: resource?.id,
          name: resource?.attributes?.name ?? "",
          is_private: Boolean(resource?.attributes?.is_private),
        });
      }

      const rawNext = body?.links?.next;
      const candidate =
        typeof rawNext === "string" && rawNext.length > 0
          ? new URL(rawNext, current)
          : null;
      // Resolved against the page it arrived on, so a cursor-only `next` keeps
      // this listing's path. Followed only while it stays on the listing's
      // origin: every page is fetched with the tenant's token, and an
      // off-origin hop made here would carry it along.
      if (candidate === null) {
        next = null;
      } else if (candidate.origin === listing.origin) {
        next = candidate.toString();
      } else {
        next = null;
        incomplete = SLACK_PARTIAL_CHANNEL_LIST_MESSAGE;
      }
    }

    // A link still waiting when the budget ran out. Checked rather than assumed
    // from the page count: a workspace of exactly `MAX_CHANNEL_PAGES` pages was
    // read to the end.
    if (next) incomplete = SLACK_PARTIAL_CHANNEL_LIST_MESSAGE;

    return incomplete === null ? { channels } : { channels, incomplete };
  } catch (error) {
    return handleApiError(error);
  }
};

interface SlackDefaultChannelSuccess {
  integration: IntegrationProps;
}

export type SlackDefaultChannelResult =
  | SlackDefaultChannelSuccess
  | SlackActionError;

/**
 * Record the channel Prowler posts to, on the generic integration endpoint.
 *
 * A Slack action despite the generic `PATCH`: `channel_not_found` and
 * `not_in_channel` carry the same `detail`, so only `code` tells them apart,
 * and the generic action reads `detail` alone. Only `channel_id` travels — the
 * API derives `channel_name` server-side (design D6).
 */
export const setSlackDefaultChannel = async (
  integrationId: string,
  channelId: string,
): Promise<SlackDefaultChannelResult> => {
  const id = parseIntegrationId(integrationId);
  if (!id) return { error: SLACK_GENERIC_ERROR_MESSAGE };

  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "integrations",
          id,
          attributes: {
            integration_type: "slack",
            configuration: { channel_id: channelId },
          },
        },
      }),
    });

    if (!response.ok) {
      return {
        error: await errorMessageFrom(
          response,
          `Unable to save the destination channel: ${response.statusText}`,
        ),
      };
    }

    const body = await response.json().catch(() => null);

    // Before the guard and on both paths: the save happened, so a cache still
    // holding the previous channel would keep showing it.
    revalidatePath("/integrations");
    revalidatePath("/integrations/slack");

    // Guarded as deep as the caller reads: it names the saved channel from
    // `attributes.configuration`.
    if (!body?.data?.attributes?.configuration) {
      return { error: SLACK_UNREADABLE_RESULT_MESSAGE };
    }

    return { integration: parseStringify(body.data) as IntegrationProps };
  } catch (error) {
    return handleApiError(error);
  }
};

interface SlackTestMessageSuccess {
  sent: true;
}

export type SlackTestMessageResult = SlackTestMessageSuccess | SlackActionError;

interface SlackTestMessageTaskResult {
  error?: string | null;
}

const TEST_MESSAGE_POLL = { maxAttempts: 20, delayMs: 3000 } as const;

/**
 * Post the test message to the integration's default channel.
 *
 * Async on the API's side — `202` plus a Task (design D9) — so this polls the
 * same task machinery the connection test uses. A `400` means no default
 * channel is recorded.
 */
export const sendSlackTestMessage = async (
  integrationId: string,
): Promise<SlackTestMessageResult> => {
  const id = parseIntegrationId(integrationId);
  if (!id) return { error: SLACK_GENERIC_ERROR_MESSAGE };

  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}/slack/test-message`);

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });

    if (!response.ok) {
      return {
        error: await errorMessageFrom(
          response,
          `Unable to send the test message: ${response.statusText}`,
        ),
      };
    }

    // As above: an unreadable `202` is "no task to follow", not a parser
    // message.
    const body = await response.json().catch(() => null);
    const taskId = body?.data?.id;

    if (!taskId) {
      return { error: "Slack did not start the test message." };
    }

    const settled = await pollTaskUntilSettled<SlackTestMessageTaskResult>(
      taskId,
      TEST_MESSAGE_POLL,
    );

    if (!settled.ok) {
      return { error: settled.error };
    }

    // Slack's refusal travels in the task result, not in an HTTP error: the
    // post happens after the `202`. A known code gets Prowler's own wording, a
    // code-shaped reason is wrapped in one (contract, test-message), and prose
    // is shown as it arrived.
    const reason = settled.result?.error?.trim();
    if (reason) {
      return {
        error: SLACK_REASON_TOKEN.test(reason)
          ? slackErrorMessage(
              { code: reason },
              slackUnknownReasonMessage(reason),
            )
          : reason,
      };
    }
    if (settled.state !== "completed") {
      return { error: "Slack did not accept the test message." };
    }

    return { sent: true };
  } catch (error) {
    return handleApiError(error);
  }
};
