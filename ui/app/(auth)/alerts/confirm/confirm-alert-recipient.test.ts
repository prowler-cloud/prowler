import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { confirmAlertRecipient } from "./confirm-alert-recipient";

const fetchMock = vi.fn();

const lastFetchCall = (): { url: string; init: RequestInit } => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const [url, init] = call;
  return { url: String(url), init: (init ?? {}) as RequestInit };
};

describe("confirmAlertRecipient", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("WEB_APP_API_BASE_URL", "https://api.example.com/api/v1");
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          state: "confirmed",
          message:
            "Your subscription has been confirmed. You will receive alert digests at this address.",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("calls the public confirmation endpoint without auth headers", async () => {
    // When
    const result = await confirmAlertRecipient("token-1");

    // Then
    expect(result).toEqual({
      ok: true,
      state: "confirmed",
      message:
        "Your subscription has been confirmed. You will receive alert digests at this address.",
    });
    const { url, init } = lastFetchCall();
    expect(url).toBe(
      "https://api.example.com/api/v1/alerts/recipients/confirm?token=token-1",
    );
    expect(init).toEqual({
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
  });

  it("returns the API message for invalid tokens", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          state: "invalid_token",
          message: "This link is invalid or has expired.",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      ),
    );

    // When
    const result = await confirmAlertRecipient("expired-token");

    // Then
    expect(result).toEqual({
      ok: false,
      state: "invalid_token",
      message: "This link is invalid or has expired.",
    });
  });

  it("returns the API message for missing tokens", async () => {
    // Given
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          state: "missing_token",
          message: "This link is missing a token.",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      ),
    );

    // When
    const result = await confirmAlertRecipient();

    // Then
    expect(result).toEqual({
      ok: false,
      state: "missing_token",
      message: "This link is missing a token.",
    });
    expect(lastFetchCall().url).toBe(
      "https://api.example.com/api/v1/alerts/recipients/confirm",
    );
  });

  it("returns the fallback message when the API base URL is missing", async () => {
    // Given
    vi.stubEnv("WEB_APP_API_BASE_URL", "");

    // When
    const result = await confirmAlertRecipient("token-1");

    // Then
    expect(result).toEqual({
      ok: false,
      state: "missing_api_base_url",
      message:
        "We could not process this confirmation link. Please try again later.",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns the fallback message when the request fails", async () => {
    // Given
    fetchMock.mockRejectedValueOnce(new Error("network down"));

    // When
    const result = await confirmAlertRecipient("token-1");

    // Then
    expect(result).toEqual({
      ok: false,
      state: "network_error",
      message:
        "We could not process this confirmation link. Please try again later.",
    });
  });
});
