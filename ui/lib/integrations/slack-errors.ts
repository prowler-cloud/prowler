/**
 * What a Slack refusal means, and what to tell the user about it.
 *
 * The API answers a Slack condition with a JSON:API error that carries the
 * machine-readable reason in `code` and human copy in `detail`. `code` is the
 * contract — this module maps it to wording Prowler owns, so no caller ever
 * parses prose. An unrecognised code falls back to the API's `detail`, and a
 * refusal carrying neither falls back to a generic line.
 *
 * The token codes are answered with `400`, not `401`, on purpose: a 401 reads
 * as "your Prowler session expired" when what died is the Slack grant. They are
 * grouped here so a caller can offer a reconnect rather than a retry.
 *
 * Rate limiting (`429`) carries no code — it is classified by status, and gets
 * its own copy so it is never confused with "this deployment has no Slack app".
 */

export const SLACK_ERROR_CODE = {
  /** The install is missing a Slack scope the action needs. */
  MISSING_SCOPE: "missing_scope",
  CHANNEL_NOT_FOUND: "channel_not_found",
  NOT_IN_CHANNEL: "not_in_channel",
  NO_PERMISSION: "no_permission",
  TOKEN_REVOKED: "token_revoked",
  INVALID_AUTH: "invalid_auth",
  ACCOUNT_INACTIVE: "account_inactive",
  TOKEN_EXPIRED: "token_expired",
  /** One workspace per tenant: another one is already connected. */
  WORKSPACE_CONFLICT: "slack_workspace_conflict",
} as const;

export type SlackErrorCode =
  (typeof SLACK_ERROR_CODE)[keyof typeof SLACK_ERROR_CODE];

/**
 * The codes that mean the Slack grant itself is no longer usable. The
 * integration is marked disconnected when one of these arrives, and the only
 * way out is connecting the workspace again — not retrying the call.
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

/** Shown when a refusal names no code and the API sent no detail either. */
export const SLACK_GENERIC_ERROR_MESSAGE =
  "Slack could not complete that request. Try again in a moment.";

export const SLACK_RATE_LIMITED_MESSAGE =
  "Slack is rate limiting Prowler right now. Try again in a few moments.";

/**
 * Shown when the API accepted the call and the UI could not read the answer: a
 * `2xx` with no body, a proxy's HTML page in place of one, a payload naming no
 * resource.
 *
 * Deliberately not phrased as a failure. The work already happened on the API
 * — it is what the `2xx` says — so telling the user their install did not go
 * through would send them to redo one that did. What Prowler cannot do is name
 * the workspace, and the integration page is where that is listed.
 */
export const SLACK_UNREADABLE_RESULT_MESSAGE =
  "Prowler could not read the result of the install. Open the Slack integration page to see the workspace — if none is listed there, start the install again.";

const RECONNECT = "Connect the workspace again to restore access.";

export const SLACK_ERROR_MESSAGES = {
  // Actionable: the user can grant the scope by reconnecting, so say that
  // rather than reporting a generic failure.
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

/** A refusal as it arrived, before it is turned into copy. */
export interface SlackApiFailure extends SlackErrorSource {
  status: number;
  /** Seconds the response asked us to wait, from `Retry-After`. */
  retryAfterSeconds: number | null;
}

const isKnownCode = (code: string | null | undefined): code is SlackErrorCode =>
  typeof code === "string" && code in SLACK_ERROR_MESSAGES;

/**
 * The copy for a refusal: the code's own wording when Prowler has one, the
 * API's `detail` when it does not, and `fallback` when there is neither.
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

/** The copy for a rate-limited response, naming the wait when Slack gave one. */
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
 * body that is not JSON:API — an HTML error page, an empty `502` — still yields
 * a failure with a status, which is what the caller acts on.
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
