import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: vi.fn(async () => ({
    Accept: "application/vnd.api+json",
    Authorization: "Bearer test-token",
  })),
}));

vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
}));

vi.mock("@sentry/nextjs", () => ({
  addBreadcrumb: vi.fn(),
  captureException: vi.fn(),
}));

import { confirmRecipient, unsubscribeRecipient } from "./public";

const captureFetchArgs = (status: number, body: unknown) => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchMock = vi.fn(async (url: RequestInfo, init?: RequestInit) => {
    calls.push({ url: url.toString(), init: init ?? {} });
    return new Response(body === null ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
};

beforeEach(() => {
  vi.unstubAllGlobals();
  process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "true";
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("confirmRecipient", () => {
  it("returns a controlled response without fetching when alerts are disabled", async () => {
    process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "false";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await confirmRecipient("token-123");

    expect(result.state).toBe("network_error");
    expect(result.message).toMatch(/Prowler Cloud/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does NOT attach Authorization header (public endpoint)", async () => {
    const calls = captureFetchArgs(200, {
      state: "confirmed",
      message: "Recipient confirmed.",
    });
    await confirmRecipient("token-123");
    const headers = (calls[0].init.headers ?? {}) as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
    expect(calls[0].url).toContain("/alerts/recipients/confirm");
    expect(calls[0].url).toContain("token=token-123");
  });

  it("returns the API state on a 200 response", async () => {
    captureFetchArgs(200, {
      state: "already_confirmed",
      message: "Already confirmed.",
    });
    const result = await confirmRecipient("token-123");
    expect(result.state).toBe("already_confirmed");
    expect(result.message).toBe("Already confirmed.");
  });

  it("surfaces invalid_token state from a 400 response", async () => {
    captureFetchArgs(400, {
      state: "invalid_token",
      message: "Token is malformed.",
    });
    const result = await confirmRecipient("bad-token");
    expect(result.state).toBe("invalid_token");
  });

  it("folds malformed bodies into network_error", async () => {
    captureFetchArgs(500, "not-json");
    const result = await confirmRecipient("token-123");
    expect(result.state).toBe("network_error");
  });
});

describe("unsubscribeRecipient", () => {
  it("hits /unsubscribe with the token and returns the API state", async () => {
    const calls = captureFetchArgs(200, {
      state: "unsubscribed",
      message: "Unsubscribed.",
    });
    const result = await unsubscribeRecipient("token-xyz");
    expect(result.state).toBe("unsubscribed");
    expect(calls[0].url).toContain("/alerts/recipients/unsubscribe");
  });
});
