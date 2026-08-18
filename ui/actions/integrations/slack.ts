"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";
import {
  readSlackFailure,
  SLACK_GENERIC_ERROR_MESSAGE,
  SLACK_UNREADABLE_RESULT_MESSAGE,
  slackErrorMessage,
  slackRateLimitMessage,
} from "@/lib/integrations/slack-errors";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import type { IntegrationProps } from "@/types/integrations";

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

/**
 * The callback names the workspace and redirects on this value alone, so a `2xx`
 * payload that is not a JSON:API resource (`{}`, `[]`, `"invalid"`) must read as
 * unreadable rather than as a connected workspace.
 */
const isIntegrationResource = (value: unknown): boolean => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }

  const { id, attributes } = value as Record<string, unknown>;

  return (
    typeof id === "string" &&
    typeof attributes === "object" &&
    attributes !== null &&
    !Array.isArray(attributes)
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
