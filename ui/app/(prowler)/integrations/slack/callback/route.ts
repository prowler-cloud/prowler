import { NextResponse } from "next/server";

import { exchangeSlackOAuthCode } from "@/actions/integrations/slack";
import type { SlackExchangeResult } from "@/actions/integrations/slack";
import {
  SLACK_CONNECT_STATUS,
  slackConnectQuery,
} from "@/lib/integrations/slack-connect-status";
import type { SlackConnectOutcomeInput } from "@/lib/integrations/slack-connect-status";
import { isCloud } from "@/lib/shared/env";

/**
 * Slack's OAuth callback, completed server-side: exchange, then an HTTP `303`
 * to the integration page with the outcome in the query string.
 *
 * A Route Handler rather than a page, like the GitHub/Google/SAML callbacks: a
 * client-side `router.replace` after the exchange rides the App Router action
 * queue, where a Server Action resolving mid-navigation can cancel it
 * (vercel/next.js#88343) — and the single-use `code` must not reach hydrated
 * client code or the session history, which the redirect guarantees.
 */

const SLACK_INTEGRATION_PATH = "/integrations/slack";

const redirectTo = (request: Request, target: string): NextResponse =>
  NextResponse.redirect(new URL(target, request.url), 303);

const outcomeRedirect = (
  request: Request,
  outcome: SlackConnectOutcomeInput,
): NextResponse =>
  redirectTo(
    request,
    `${SLACK_INTEGRATION_PATH}?${slackConnectQuery(outcome)}`,
  );

/**
 * `Sec-Purpose` per the fetch spec; `Purpose` and `X-moz` are the legacy
 * Chrome/Safari and Firefox spellings.
 */
const isPrefetch = (request: Request): boolean => {
  const purpose =
    request.headers.get("sec-purpose") ??
    request.headers.get("purpose") ??
    request.headers.get("x-moz") ??
    "";
  return purpose.toLowerCase().includes("prefetch");
};

/**
 * Explicit, because Next otherwise auto-implements HEAD by running the GET —
 * which would exchange (and burn) the single-use code before the user's own
 * GET arrives.
 */
export function HEAD(): Response {
  return new Response(null, { status: 204 });
}

export async function GET(request: Request): Promise<NextResponse> {
  if (!isCloud()) return redirectTo(request, "/");

  // A speculative fetch would burn the single-use code before the user
  // arrives — answer it nothing instead.
  if (isPrefetch(request)) return new NextResponse(null, { status: 204 });

  const { searchParams } = new URL(request.url);
  const slackError = searchParams.get("error");
  const code = searchParams.get("code");
  const state = searchParams.get("state");

  // Slack answers a declined install with `error` and no code; when both are
  // present, `error` still wins and nothing is exchanged.
  if (slackError) {
    return outcomeRedirect(request, {
      status: SLACK_CONNECT_STATUS.SLACK_ERROR,
      reason: slackError,
    });
  }

  if (!code || !state) {
    return outcomeRedirect(request, {
      status: SLACK_CONNECT_STATUS.INCOMPLETE,
    });
  }

  let result: SlackExchangeResult;
  try {
    result = await exchangeSlackOAuthCode({ code, state });
  } catch {
    // The action is written to never throw; if it does anyway, the API may
    // already have upserted the integration, so the claim is "unconfirmed",
    // not "failed".
    return outcomeRedirect(request, {
      status: SLACK_CONNECT_STATUS.UNCONFIRMED,
    });
  }

  if ("integration" in result) {
    return outcomeRedirect(request, {
      status: SLACK_CONNECT_STATUS.CONNECTED,
    });
  }
  if ("unavailable" in result) {
    return outcomeRedirect(request, {
      status: SLACK_CONNECT_STATUS.UNAVAILABLE,
    });
  }
  if ("rateLimited" in result) {
    return outcomeRedirect(request, {
      status: SLACK_CONNECT_STATUS.RATE_LIMITED,
      retryAfterSeconds: result.retryAfterSeconds,
    });
  }
  if ("unconfirmed" in result) {
    return outcomeRedirect(request, {
      status: SLACK_CONNECT_STATUS.UNCONFIRMED,
    });
  }
  // A 400 naming no reason is the exchange's "state or code already consumed
  // or timed out" refusal — the back button's path. Retrying cannot help, so
  // it gets its own status rather than the generic "try again" error.
  if (!result.code && result.status === 400) {
    return outcomeRedirect(request, { status: SLACK_CONNECT_STATUS.EXPIRED });
  }
  return outcomeRedirect(request, {
    status: SLACK_CONNECT_STATUS.ERROR,
    code: result.code ?? null,
  });
}
