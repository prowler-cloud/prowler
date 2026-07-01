const DEFAULT_CALLBACK_PATH = "/";
const INVITATION_TOKEN_PARAM = "invitation_token";

type CallbackSearchParams = {
  get(name: string): string | null;
};

export const getSafeCallbackPathFromValue = (
  value: string | null | undefined,
) => {
  if (!value || !value.startsWith("/") || value.startsWith("//")) {
    return DEFAULT_CALLBACK_PATH;
  }

  return value;
};

export const getSafeCallbackPath = (
  searchParams: CallbackSearchParams,
  key = "state",
) => getSafeCallbackPathFromValue(searchParams.get(key));

export const appendCallbackState = (authUrl: string, callbackPath: string) => {
  const safeCallbackPath = getSafeCallbackPathFromValue(callbackPath);
  if (safeCallbackPath === DEFAULT_CALLBACK_PATH) {
    return authUrl;
  }

  try {
    const url = new URL(authUrl);
    url.searchParams.set("state", safeCallbackPath);
    return url.toString();
  } catch (_error) {
    return authUrl;
  }
};

export const getInvitationTokenFromCallbackPath = (callbackPath: string) => {
  const safeCallbackPath = getSafeCallbackPathFromValue(callbackPath);
  if (safeCallbackPath === DEFAULT_CALLBACK_PATH) {
    return null;
  }

  try {
    const url = new URL(safeCallbackPath, "http://localhost");
    return url.searchParams.get(INVITATION_TOKEN_PARAM);
  } catch (_error) {
    return null;
  }
};
