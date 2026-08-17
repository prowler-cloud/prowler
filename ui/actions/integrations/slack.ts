"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";
import {
  readSlackFailure,
  SLACK_UNREADABLE_RESULT_MESSAGE,
  slackErrorMessage,
  slackRateLimitMessage,
} from "@/lib/integrations/slack-errors";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import type { IntegrationProps } from "@/types/integrations";

/**
 * The two OAuth calls the Slack install needs. Everything else — reading the
 * integration, testing the connection, deleting it — goes through the generic
 * integration actions, because Slack rows are plain `integrations` resources.
 *
 * The Slack app (`SLACK_CLIENT_ID` / `SLACK_CLIENT_SECRET` /
 * `SLACK_REDIRECT_URI`) is a deployment-wide setting, so both endpoints answer
 * `503` until it is configured, and a deployment that serves no Slack API at
 * all answers `404`. Neither is an error the user can act on: both mean "Slack
 * isn't available in this environment yet", which is why they get their own
 * result shape rather than an error string.
 *
 * Rate limiting is a third answer again — Slack is there, the deployment is
 * configured, and the only thing to do is wait — so it gets its own outcome
 * rather than being folded into either of the other two.
 *
 * The OAuth `state` is minted and consumed by the API, bound to the tenant and
 * the user — the UI never inspects it, it only forwards what Slack sent back.
 */

interface SlackUnavailable {
  unavailable: true;
}

/**
 * Slack is rate limiting Prowler (`429`). Distinct from `SlackUnavailable`: the
 * Slack app exists and works, so the page keeps offering what it offers and
 * only says when to come back.
 */
interface SlackRateLimited {
  rateLimited: true;
  /** What `Retry-After` asked for, when the response carried one. */
  retryAfterSeconds: number | null;
  /** The wait, as copy — so every caller says the same thing about it. */
  message: string;
}

/**
 * The API accepted the completion and the UI could not read the answer back.
 *
 * Its own outcome rather than an error, for the same reason `unavailable` and
 * `rateLimited` are: `response.ok` was true, so the code was consumed and the
 * integration upserted — what Prowler cannot name is the workspace, not whether
 * one was connected. Callers that report an error would be reporting the one
 * thing this answer rules out.
 */
interface SlackUnconfirmed {
  unconfirmed: true;
  /** The unread result, as copy — so every caller says the same thing about it. */
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
 * Whether the deployment answered "no Slack app here". Deliberately narrow:
 * widening it to a status that only means "not right now" (a `429`, an upstream
 * `502`) would tell the user Slack is unavailable in their environment when it
 * is Prowler's call that needs retrying.
 */
const isUnavailableStatus = (status: number): boolean =>
  status === 503 || status === 404;

const RATE_LIMITED_STATUS = 429;

/**
 * Classify a refusal into the outcome the UI acts on.
 *
 * The reason travels in the JSON:API error's `code`, which
 * `slackErrorMessage` maps to copy Prowler owns; `detail` is the API's own
 * human wording and is used only when the code is one this UI has nothing
 * better to say about. `fallback` covers a refusal that carries neither.
 */
const failureFrom = async (
  response: Response,
  fallback: string,
): Promise<SlackUnavailable | SlackRateLimited | SlackActionError> => {
  if (isUnavailableStatus(response.status)) return { unavailable: true };

  // A 5xx that is not the ship-dark 503 is a server fault rather than a Slack
  // state — and `502` is the status the contract reserves for "Slack upstream
  // broke" — so it goes through the repo's own 5xx handling, which is where
  // Sentry hears about one. That call reports *and throws*, so each action's
  // existing catch is what answers the user. It has to run before
  // `readSlackFailure`: a response body can only be read once.
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
 * Mint an OAuth state and get the consent URL to send the user to. Creates no
 * integration: the install only exists once the exchange completes.
 */
export const getSlackAuthorizeUrl =
  async (): Promise<SlackAuthorizeUrlResult> => {
    const headers = await getAuthHeaders({ contentType: true });
    const url = new URL(`${apiBaseUrl}/integrations/slack/oauth/authorize-url`);

    try {
      const response = await fetch(url.toString(), { method: "POST", headers });

      if (!response.ok) {
        // Awaited inside the `try`: a returned promise's rejection is not this
        // `catch`'s to see, and a 5xx now rejects.
        return await failureFrom(
          response,
          `Unable to start the Slack install: ${response.statusText}`,
        );
      }

      // The URL travels in JSON:API `meta` — the call creates no resource. A
      // `2xx` that is not JSON at all (a proxy's HTML page, an empty body) is
      // read as "no URL here" rather than left to throw a parser message the
      // user would be shown verbatim.
      const body = await response.json().catch(() => null);
      const authorizeUrl = body?.meta?.authorize_url;

      if (typeof authorizeUrl !== "string" || authorizeUrl.length === 0) {
        return { error: "Slack did not return an authorization URL." };
      }

      return { authorizeUrl };
    } catch (error) {
      return handleApiError(error);
    }
  };

/**
 * Complete the install with what Slack put in the callback URL. The API
 * validates and consumes the `state`, exchanges the single-use `code`, and
 * upserts the tenant's Slack integration.
 */
export const exchangeSlackOAuthCode = async ({
  code,
  state,
}: SlackExchangeInput): Promise<SlackExchangeResult> => {
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
      // A refused state and a code Slack rejected arrive as a `400` whose
      // `detail` is the reason to show. "A different workspace is already
      // connected" is a `409` named by its `code`, which is what turns it into
      // copy that says how to get out of it.
      // Awaited inside the `try`, as above: unawaited, a 5xx's rejection would
      // pass this `catch` and leave the callback on its spinner.
      return await failureFrom(
        response,
        `Unable to connect the Slack workspace: ${response.statusText}`,
      );
    }

    // A `2xx` the UI cannot read is still a completed exchange: a `204`, an
    // empty body, a proxy's HTML page. Parsing it as it arrives would throw a
    // V8 parser message that travels the catch below straight to the user.
    const body = await response.json().catch(() => null);

    // Revalidated before the guard, and on both paths. The API consumed the
    // code and upserted the integration before answering, so the workspace is
    // connected whatever came back: serving the pages that list it from a cache
    // filled when there was none would report a connected workspace as missing.
    revalidatePath("/integrations");
    revalidatePath("/integrations/slack");

    // Reported as its own outcome rather than as a connected workspace with no
    // name: the callback reads `attributes.configuration` off this, and a
    // fabricated resource would fail there instead, further from the cause.
    // Not an `{ error }` either — the `2xx` says the install happened, so a
    // caller reading this as a failure would deny the one fact it establishes.
    if (!body?.data) {
      return { unconfirmed: true, message: SLACK_UNREADABLE_RESULT_MESSAGE };
    }

    return { integration: parseStringify(body.data) as IntegrationProps };
  } catch (error) {
    return handleApiError(error);
  }
};
