const DEFAULT_CALLBACK_PATH = "/";
const INVITATION_TOKEN_PARAM = "invitation_token";
// Origin used only to resolve relative paths; never part of the returned value.
const INTERNAL_ORIGIN = "http://localhost";

type CallbackSearchParams = {
  get(name: string): string | null;
};

export const getSafeCallbackPathFromValue = (
  value: string | null | undefined,
) => {
  if (!value || !value.startsWith("/") || value.startsWith("//")) {
    return DEFAULT_CALLBACK_PATH;
  }

  // A prefix check is not enough: the URL parser normalizes backslashes and
  // control characters, so "/\evil.com" or "/\t/evil.com" pass the check above
  // yet resolve to an external origin. Resolve against a fixed origin and
  // confirm it stayed internal before trusting the path.
  try {
    const url = new URL(value, INTERNAL_ORIGIN);
    if (url.origin !== INTERNAL_ORIGIN) {
      return DEFAULT_CALLBACK_PATH;
    }

    return `${url.pathname}${url.search}${url.hash}`;
  } catch (_error) {
    return DEFAULT_CALLBACK_PATH;
  }
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
