"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";
import { handleApiError } from "@/lib/server-actions-helper";
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
 * The OAuth `state` is minted and consumed by the API, bound to the tenant and
 * the user — the UI never inspects it, it only forwards what Slack sent back.
 */

interface SlackUnavailable {
  unavailable: true;
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
  | SlackActionError;

/** Whether the deployment answered "no Slack app here". */
const isUnavailableStatus = (status: number): boolean =>
  status === 503 || status === 404;

const detailFrom = async (
  response: Response,
  fallback: string,
): Promise<string> => {
  const body = await response.json().catch(() => ({}));
  return body?.errors?.[0]?.detail || fallback;
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

      if (isUnavailableStatus(response.status)) {
        return { unavailable: true };
      }

      if (!response.ok) {
        return {
          error: await detailFrom(
            response,
            `Unable to start the Slack install: ${response.statusText}`,
          ),
        };
      }

      // The URL travels in JSON:API `meta` — the call creates no resource.
      const body = await response.json();
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

    if (isUnavailableStatus(response.status)) {
      return { unavailable: true };
    }

    if (!response.ok) {
      // A refused state, a code Slack rejected and "a different workspace is
      // already connected" all arrive as a 400 whose detail is the reason to
      // show — the UI does not need to tell them apart.
      return {
        error: await detailFrom(
          response,
          `Unable to connect the Slack workspace: ${response.statusText}`,
        ),
      };
    }

    const body = await response.json();

    revalidatePath("/integrations");
    revalidatePath("/integrations/slack");

    return { integration: parseStringify(body.data) as IntegrationProps };
  } catch (error) {
    return handleApiError(error);
  }
};
