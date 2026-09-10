import { extractUtmParams, type UtmParams } from "@/lib/utm";

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

export const appendAttributionToCallbackPath = (
  callbackPath: string,
  attribution: UtmParams,
): string => {
  const safeCallbackPath = getSafeCallbackPathFromValue(callbackPath);
  if (Object.keys(attribution).length === 0) {
    return safeCallbackPath;
  }

  try {
    const url = new URL(safeCallbackPath, INTERNAL_ORIGIN);
    for (const [key, value] of Object.entries(attribution)) {
      if (!url.searchParams.has(key)) {
        url.searchParams.set(key, value);
      }
    }
    return `${url.pathname}${url.search}${url.hash}`;
  } catch (_error) {
    return safeCallbackPath;
  }
};

export const getAttributionParamsFromCallbackPath = (
  callbackPath: string,
): UtmParams => {
  const safeCallbackPath = getSafeCallbackPathFromValue(callbackPath);

  try {
    const url = new URL(safeCallbackPath, INTERNAL_ORIGIN);
    return extractUtmParams(url.searchParams);
  } catch (_error) {
    return {};
  }
};
