import { NextResponse } from "next/server";

import { exchangeSlackOAuthCode } from "@/actions/integrations/slack";
import type { SlackExchangeResult } from "@/actions/integrations/slack";
import {
  SLACK_INTEGRATION_PATH,
  SLACK_CONNECT_STATUS,
  slackConnectQuery,
} from "@/lib/integrations/slack-connect-status";
import type { SlackConnectOutcomeInput } from "@/lib/integrations/slack-connect-status";
import { SLACK_ERROR_CODE } from "@/lib/integrations/slack-errors";
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

const noStoreNoContent = (): NextResponse =>
  new NextResponse(null, {
    status: 204,
    headers: { "Cache-Control": "no-store" },
  });

/**
 * Relative `Location`, built by hand because `NextResponse.redirect` insists
 * on an absolute URL: behind a reverse proxy `request.url` carries the
 * internal Host, not the domain the browser used, so an absolute URL built
 * from it strands the browser on an unresolvable host. The browser resolves a
 * relative Location against the origin it reached the callback on.
 */
const redirectTo = (target: string): NextResponse =>
  new NextResponse(null, { status: 303, headers: { Location: target } });

const outcomeRedirect = (outcome: SlackConnectOutcomeInput): NextResponse =>
  redirectTo(`${SLACK_INTEGRATION_PATH}?${slackConnectQuery(outcome)}`);

/**
 * `Sec-Purpose` per the fetch spec; `Purpose` and `X-moz` are the legacy
 * Chrome/Safari and Firefox spellings.
 */
const isPrefetch = (request: Request): boolean => {
  return ["sec-purpose", "purpose", "x-moz"].some(
    (header) =>
      request.headers.get(header)?.toLowerCase().includes("prefetch") ?? false,
  );
};

/**
 * Explicit, because Next otherwise auto-implements HEAD by running the GET —
 * which would exchange (and burn) the single-use code before the user's own
 * GET arrives.
 */
export function HEAD(): Response {
  return noStoreNoContent();
}

export async function GET(request: Request): Promise<NextResponse> {
  if (!isCloud()) return redirectTo("/");

  // A speculative fetch would burn the single-use code before the user
  // arrives — answer it nothing instead.
  if (isPrefetch(request)) return noStoreNoContent();

  const { searchParams } = new URL(request.url);
  const slackError = searchParams.get("error");
  const code = searchParams.get("code");
  const state = searchParams.get("state");

  // Slack answers a declined install with `error` and no code; when both are
  // present, `error` still wins and nothing is exchanged.
  if (slackError) {
    return outcomeRedirect({
      status: SLACK_CONNECT_STATUS.SLACK_ERROR,
      reason: slackError,
    });
  }

  if (!code || !state) {
    return outcomeRedirect({
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
    return outcomeRedirect({
      status: SLACK_CONNECT_STATUS.UNCONFIRMED,
    });
  }

  if ("integration" in result) {
    return outcomeRedirect({
      status: SLACK_CONNECT_STATUS.CONNECTED,
    });
  }
  if ("unavailable" in result) {
    return outcomeRedirect({
      status: SLACK_CONNECT_STATUS.UNAVAILABLE,
    });
  }
  if ("rateLimited" in result) {
    return outcomeRedirect({
      status: SLACK_CONNECT_STATUS.RATE_LIMITED,
      retryAfterSeconds: result.retryAfterSeconds,
    });
  }
  if ("unconfirmed" in result) {
    return outcomeRedirect({
      status: SLACK_CONNECT_STATUS.UNCONFIRMED,
    });
  }
  // The exchange's "state or code already consumed or timed out" refusal —
  // the back button's path. The contract words it as a 400 naming no reason;
  // the deployed API names `invalid_oauth_state` on the same refusal, so both
  // spellings land here. Retrying cannot help, so it gets its own status
  // rather than the generic "try again" error.
  if (
    result.status === 400 &&
    (!result.code || result.code === SLACK_ERROR_CODE.INVALID_OAUTH_STATE)
  ) {
    return outcomeRedirect({ status: SLACK_CONNECT_STATUS.EXPIRED });
  }
  return outcomeRedirect({
    status: SLACK_CONNECT_STATUS.ERROR,
    code: result.code ?? null,
  });
}
