/**
 * The status-param contract between the OAuth callback Route Handler and the
 * notice on the Slack integration page: the handler writes the install's
 * outcome into its redirect's query string, the notice reads it back. Tokens
 * only, never free text — everything here rides the URL, so both sides gate
 * every value on its shape before it travels or renders.
 */
import { SLACK_REASON_TOKEN } from "@/lib/integrations/slack-errors";

export const SLACK_CONNECT_STATUS = {
  CONNECTED: "connected",
  /** Slack itself refused the install (`?error=` on the callback). */
  SLACK_ERROR: "slack_error",
  /** The callback carried no usable `code`/`state` pair. */
  INCOMPLETE: "incomplete",
  /** The state or single-use code had already been consumed or timed out. */
  EXPIRED: "expired",
  UNAVAILABLE: "unavailable",
  RATE_LIMITED: "rate_limited",
  /** The API may have connected the workspace; its answer was unreadable. */
  UNCONFIRMED: "unconfirmed",
  /** The API refused the exchange, optionally naming a reason in `code`. */
  ERROR: "error",
} as const;

export type SlackConnectStatus =
  (typeof SLACK_CONNECT_STATUS)[keyof typeof SLACK_CONNECT_STATUS];

const SLACK_STATUS_PARAM = "slack";
const SLACK_REASON_PARAM = "slack_reason";
const SLACK_CODE_PARAM = "slack_code";
const SLACK_RETRY_PARAM = "slack_retry";

/** Every param the contract owns — what the notice strips from the URL. */
export const SLACK_CONNECT_PARAMS = [
  SLACK_STATUS_PARAM,
  SLACK_REASON_PARAM,
  SLACK_CODE_PARAM,
  SLACK_RETRY_PARAM,
] as const;

export interface SlackConnectOutcome {
  status: SlackConnectStatus;
  /** Slack's `?error` token; only with `slack_error`. */
  reason: string | null;
  /** The API refusal's `code`; only with `error`. */
  code: string | null;
  /** Only with `rate_limited`. */
  retryAfterSeconds: number | null;
}

export interface SlackConnectOutcomeInput {
  status: SlackConnectStatus;
  reason?: string | null;
  code?: string | null;
  retryAfterSeconds?: number | null;
}

const RETRY_SECONDS = /^\d{1,6}$/;

const STATUS_VALUES = new Set<string>(Object.values(SLACK_CONNECT_STATUS));

const isStatus = (value: string | null): value is SlackConnectStatus =>
  value !== null && STATUS_VALUES.has(value);

const tokenOrNull = (value: string | null | undefined): string | null =>
  value && SLACK_REASON_TOKEN.test(value) ? value : null;

/** A `Retry-After` can be fractional; the wait copy rounds up anyway. */
const retryParamValue = (value: number | null | undefined): string | null => {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return null;
  }
  const text = String(Math.ceil(value));
  return RETRY_SECONDS.test(text) ? text : null;
};

export const slackConnectQuery = (
  outcome: SlackConnectOutcomeInput,
): URLSearchParams => {
  const params = new URLSearchParams();
  params.set(SLACK_STATUS_PARAM, outcome.status);

  const reason = tokenOrNull(outcome.reason);
  if (reason) params.set(SLACK_REASON_PARAM, reason);

  const code = tokenOrNull(outcome.code);
  if (code) params.set(SLACK_CODE_PARAM, code);

  const retry = retryParamValue(outcome.retryAfterSeconds);
  if (retry) params.set(SLACK_RETRY_PARAM, retry);

  return params;
};

/**
 * `null` for a query that carries no (recognisable) outcome, so a page visit
 * that did not come through the callback renders no notice.
 */
export const readSlackConnectOutcome = (
  params: URLSearchParams,
): SlackConnectOutcome | null => {
  const status = params.get(SLACK_STATUS_PARAM);
  if (!isStatus(status)) return null;

  const retry = params.get(SLACK_RETRY_PARAM);

  return {
    status,
    reason: tokenOrNull(params.get(SLACK_REASON_PARAM)),
    code: tokenOrNull(params.get(SLACK_CODE_PARAM)),
    retryAfterSeconds:
      retry !== null && RETRY_SECONDS.test(retry) ? Number(retry) : null,
  };
};
