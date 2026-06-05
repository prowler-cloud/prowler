interface AlertConfirmApiResponse {
  state?: string;
  message?: string;
}

interface AlertConfirmResult {
  ok: boolean;
  state: string;
  message: string;
}

const FALLBACK_CONFIRM_ERROR =
  "We could not process this confirmation link. Please try again later.";

const toMessage = (payload: unknown): string | null => {
  if (
    typeof payload === "object" &&
    payload !== null &&
    "message" in payload &&
    typeof payload.message === "string"
  ) {
    return payload.message;
  }

  return null;
};

const toState = (payload: unknown): string => {
  if (
    typeof payload === "object" &&
    payload !== null &&
    "state" in payload &&
    typeof payload.state === "string"
  ) {
    return payload.state;
  }

  return "unknown";
};

export const confirmAlertRecipient = async (
  token?: string,
): Promise<AlertConfirmResult> => {
  const apiBaseUrl = process.env.WEB_APP_API_BASE_URL;
  if (!apiBaseUrl) {
    return {
      ok: false,
      state: "missing_api_base_url",
      message: FALLBACK_CONFIRM_ERROR,
    };
  }

  const url = new URL(`${apiBaseUrl}/alerts/recipients/confirm`);
  if (token) {
    url.searchParams.set("token", token);
  }

  try {
    const response = await fetch(url.toString(), {
      headers: {
        Accept: "application/json",
      },
      cache: "no-store",
    });
    const payload = (await response.json()) as AlertConfirmApiResponse;

    return {
      ok: response.ok,
      state: toState(payload),
      message: toMessage(payload) ?? FALLBACK_CONFIRM_ERROR,
    };
  } catch {
    return {
      ok: false,
      state: "network_error",
      message: FALLBACK_CONFIRM_ERROR,
    };
  }
};
