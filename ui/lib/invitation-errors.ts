import type { ApiError, ApiResponse } from "@/types";

const INVITATION_ERROR_DETAIL = {
  NO_LONGER_VALID: "This invitation is no longer valid.",
} as const;

const INVITATION_ERROR_POINTER = {
  DATA: "/data",
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
  expired:
    "This invitation has expired. Please contact your administrator for a new one.",
  noLongerValid:
    "This invitation is no longer valid. Please contact your administrator for a new invitation.",
  notValid: "This invitation is not valid. Please check the link you received.",
  invalidFallback:
    "This invitation is invalid. Please check the link or contact your administrator.",
  unexpected: "Something went wrong while accepting the invitation.",
} as const;

interface InvitationErrorDisplay {
  message: string;
  canRetry: boolean;
  needsSignOut: boolean;
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
  return (
    error.source?.pointer === INVITATION_ERROR_POINTER.DATA ||
    error.source?.pointer === INVITATION_ERROR_POINTER.INVITATION_TOKEN
  );
}

export function getInvitationErrorDisplay(
  response: InvitationErrorResponse,
  flow: InvitationErrorFlow,
): InvitationErrorDisplay {
  const firstError = getFirstError(response);
  const code = firstError?.code;
  const detail = firstError?.detail;

  if (response.status === 410 && code === INVITATION_ERROR_CODE.TOKEN_EXPIRED) {
    return {
      message: INVITATION_ERROR_MESSAGES.expired,
      canRetry: false,
      needsSignOut: false,
    };
  }

  if (
    response.status === 400 &&
    code === INVITATION_ERROR_CODE.INVALID &&
    detail === INVITATION_ERROR_DETAIL.NO_LONGER_VALID
  ) {
    return {
      message: INVITATION_ERROR_MESSAGES.noLongerValid,
      canRetry: false,
      needsSignOut: false,
    };
  }

  if (response.status === 404 && code === INVITATION_ERROR_CODE.NOT_FOUND) {
    return {
      message: INVITATION_ERROR_MESSAGES.notValid,
      canRetry: false,
      needsSignOut: false,
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
      message: INVITATION_ERROR_MESSAGES.notValid,
      canRetry: false,
      needsSignOut: false,
    };
  }

  if (code === INVITATION_ERROR_CODE.INVALID) {
    return {
      message: INVITATION_ERROR_MESSAGES.invalidFallback,
      canRetry: false,
      needsSignOut: false,
    };
  }

  return {
    message: INVITATION_ERROR_MESSAGES.unexpected,
    canRetry: true,
    needsSignOut: false,
  };
}
