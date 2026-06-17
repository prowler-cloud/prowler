import type { ApiError, ApiResponse } from "@/types";

const CLIENT_INVITATION_ERROR = {
  INVALID_TOKEN: "Invalid invitation token",
} as const;

const INVITATION_ERROR_DETAIL = {
  NO_LONGER_VALID: "This invitation is no longer valid.",
} as const;

const INVITATION_ERROR_POINTER = {
  INVITATION_TOKEN: "/data/attributes/invitation_token",
} as const;

const INVITATION_ERROR_CODE = {
  INVALID: "invalid",
  NOT_FOUND: "not_found",
  TOKEN_EXPIRED: "token_expired",
} as const;

export const INVITATION_ERROR_FLOW = {
  ACCEPT: "accept",
  SIGNUP: "signup",
} as const;

type InvitationErrorFlow =
  (typeof INVITATION_ERROR_FLOW)[keyof typeof INVITATION_ERROR_FLOW];

export const INVITATION_ERROR_MESSAGES = {
  EXPIRED:
    "This invitation has expired. Please contact your administrator for a new one.",
  NO_LONGER_VALID:
    "This invitation is no longer valid. Please contact your administrator for a new invitation.",
  NOT_VALID:
    "This invitation is not valid. Please check the link you received.",
  INVALID_FALLBACK:
    "This invitation is invalid. Please check the link or contact your administrator.",
  UNEXPECTED: "Something went wrong while accepting the invitation.",
} as const;

interface InvitationErrorDisplay {
  message: string;
  canRetry: boolean;
}

interface InvitationErrorResponse
  extends Pick<ApiResponse, "error" | "status"> {
  errors?: ApiError[];
}

function getFirstError(
  response: InvitationErrorResponse,
): ApiError | undefined {
  return response.errors?.[0];
}

export function isInvitationTokenError(error: ApiError): boolean {
  return error.source?.pointer === INVITATION_ERROR_POINTER.INVITATION_TOKEN;
}

export function getInvitationErrorDisplay(
  response: InvitationErrorResponse,
  flow: InvitationErrorFlow,
): InvitationErrorDisplay {
  const firstError = getFirstError(response);
  const code = firstError?.code;
  const detail = firstError?.detail;

  if (response.error === CLIENT_INVITATION_ERROR.INVALID_TOKEN) {
    return {
      message: INVITATION_ERROR_MESSAGES.INVALID_FALLBACK,
      canRetry: false,
    };
  }

  if (response.status === 410 && code === INVITATION_ERROR_CODE.TOKEN_EXPIRED) {
    return {
      message: INVITATION_ERROR_MESSAGES.EXPIRED,
      canRetry: false,
    };
  }

  if (
    response.status === 400 &&
    code === INVITATION_ERROR_CODE.INVALID &&
    detail === INVITATION_ERROR_DETAIL.NO_LONGER_VALID
  ) {
    return {
      message: INVITATION_ERROR_MESSAGES.NO_LONGER_VALID,
      canRetry: false,
    };
  }

  if (response.status === 404 && code === INVITATION_ERROR_CODE.NOT_FOUND) {
    return {
      message: INVITATION_ERROR_MESSAGES.NOT_VALID,
      canRetry: false,
    };
  }

  if (
    flow === INVITATION_ERROR_FLOW.SIGNUP &&
    response.status === 400 &&
    code === INVITATION_ERROR_CODE.INVALID &&
    firstError &&
    isInvitationTokenError(firstError)
  ) {
    return {
      message: INVITATION_ERROR_MESSAGES.NOT_VALID,
      canRetry: false,
    };
  }

  if (code === INVITATION_ERROR_CODE.INVALID) {
    return {
      message: INVITATION_ERROR_MESSAGES.INVALID_FALLBACK,
      canRetry: false,
    };
  }

  return {
    message: INVITATION_ERROR_MESSAGES.UNEXPECTED,
    canRetry: true,
  };
}
