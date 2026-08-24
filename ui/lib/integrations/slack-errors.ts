export const SLACK_ERROR_CODE = {
  MISSING_SCOPE: "missing_scope",
  CHANNEL_NOT_FOUND: "channel_not_found",
  NOT_IN_CHANNEL: "not_in_channel",
  NO_PERMISSION: "no_permission",
  TOKEN_REVOKED: "token_revoked",
  INVALID_AUTH: "invalid_auth",
  ACCOUNT_INACTIVE: "account_inactive",
  TOKEN_EXPIRED: "token_expired",
  /** One workspace per tenant. */
  WORKSPACE_CONFLICT: "slack_workspace_conflict",
} as const;

export type SlackErrorCode =
  (typeof SLACK_ERROR_CODE)[keyof typeof SLACK_ERROR_CODE];

/**
 * The grant itself is dead: reconnecting is the only way out, not retrying. The
 * API answers these with `400`, not `401`, so they are not mistaken for an
 * expired Prowler session.
 */
export const SLACK_TOKEN_ERROR_CODES = [
  SLACK_ERROR_CODE.TOKEN_REVOKED,
  SLACK_ERROR_CODE.INVALID_AUTH,
  SLACK_ERROR_CODE.ACCOUNT_INACTIVE,
  SLACK_ERROR_CODE.TOKEN_EXPIRED,
] as const;

export type SlackTokenErrorCode = (typeof SLACK_TOKEN_ERROR_CODES)[number];

export const isSlackTokenErrorCode = (
  code: string | null | undefined,
): code is SlackTokenErrorCode =>
  SLACK_TOKEN_ERROR_CODES.includes(code as SlackTokenErrorCode);

export const SLACK_GENERIC_ERROR_MESSAGE =
  "Slack could not complete that request. Try again in a moment.";

export const SLACK_RATE_LIMITED_MESSAGE =
  "Slack is rate limiting Prowler right now. Try again in a few moments.";

/**
 * For a channel list that stopped short of the workspace: the page budget ran
 * out, or `links.next` left the API's origin.
 */
export const SLACK_PARTIAL_CHANNEL_LIST_MESSAGE =
  "This workspace has more channels than Prowler reads in one go, so this list is not all of them. A channel missing from it is not necessarily one @Prowler has to be invited to.";

/**
 * For a `2xx` the UI could not read. Not phrased as a failure: the install
 * happened, only the workspace cannot be named.
 */
export const SLACK_UNREADABLE_RESULT_MESSAGE =
  "Prowler could not read the result of the install. Open the Slack integration page to see the workspace — if none is listed there, start the install again.";

/**
 * The shape of a Slack reason code, as opposed to a sentence: the set is
 * open-ended, so a reason is gated on its shape before being interpolated.
 */
export const SLACK_REASON_TOKEN = /^[a-z0-9_]{1,48}$/;

const RECONNECT = "Connect the workspace again to restore access.";

export const SLACK_ERROR_MESSAGES = {
  [SLACK_ERROR_CODE.MISSING_SCOPE]:
    "Prowler is missing a permission it needs in Slack. Connect the workspace again and approve the access Prowler asks for.",
  [SLACK_ERROR_CODE.CHANNEL_NOT_FOUND]:
    "That channel no longer exists in the workspace. Choose another one.",
  [SLACK_ERROR_CODE.NOT_IN_CHANNEL]:
    "Prowler is not in that channel. Invite @Prowler to it in Slack, or choose a channel it can already post to.",
  [SLACK_ERROR_CODE.NO_PERMISSION]:
    "Slack did not allow Prowler to post there. Choose another channel, or ask a workspace admin to allow it.",
  [SLACK_ERROR_CODE.TOKEN_REVOKED]: `Prowler's access to Slack was revoked. ${RECONNECT}`,
  [SLACK_ERROR_CODE.INVALID_AUTH]: `Slack no longer accepts Prowler's credential. ${RECONNECT}`,
  [SLACK_ERROR_CODE.ACCOUNT_INACTIVE]: `The Slack account Prowler was installed with is no longer active. ${RECONNECT}`,
  [SLACK_ERROR_CODE.TOKEN_EXPIRED]: `Prowler's Slack credential has expired. ${RECONNECT}`,
  [SLACK_ERROR_CODE.WORKSPACE_CONFLICT]:
    "Prowler is already connected to a different Slack workspace. Disconnect it before connecting another one.",
} as const satisfies Record<SlackErrorCode, string>;

/** The parts of a JSON:API error this mapping reads. */
export interface SlackErrorSource {
  code?: string | null;
  detail?: string | null;
}

export interface SlackApiFailure extends SlackErrorSource {
  status: number;
  retryAfterSeconds: number | null;
}

const isKnownCode = (code: string | null | undefined): code is SlackErrorCode =>
  typeof code === "string" &&
  Object.prototype.hasOwnProperty.call(SLACK_ERROR_MESSAGES, code);

/**
 * Copy for a refusal: Prowler's wording for a known `code`, else the API's
 * `detail`, else `fallback`.
 */
export const slackErrorMessage = (
  error: SlackErrorSource | null | undefined,
  fallback: string = SLACK_GENERIC_ERROR_MESSAGE,
): string => {
  if (isKnownCode(error?.code)) return SLACK_ERROR_MESSAGES[error.code];
  return error?.detail?.trim() || fallback;
};

const describeWait = (seconds: number): string => {
  if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
};

export const slackRateLimitMessage = (
  retryAfterSeconds: number | null,
): string => {
  if (retryAfterSeconds === null || retryAfterSeconds <= 0) {
    return SLACK_RATE_LIMITED_MESSAGE;
  }
  return `Slack is rate limiting Prowler right now. Try again in about ${describeWait(
    Math.ceil(retryAfterSeconds),
  )}.`;
};

const retryAfterFrom = (response: Response): number | null => {
  const header = response.headers.get("retry-after");
  if (!header) return null;
  const seconds = Number(header.trim());
  return Number.isFinite(seconds) && seconds > 0 ? seconds : null;
};

/**
 * Read a non-OK Slack response into the failure it describes. Never throws: a
 * body that is not JSON:API still yields a failure carrying the status.
 */
export const readSlackFailure = async (
  response: Response,
): Promise<SlackApiFailure> => {
  const body = await response.json().catch(() => null);
  const error = Array.isArray(body?.errors) ? body.errors[0] : null;

  return {
    status: response.status,
    code: typeof error?.code === "string" ? error.code : null,
    detail: typeof error?.detail === "string" ? error.detail : null,
    retryAfterSeconds: retryAfterFrom(response),
  };
};
