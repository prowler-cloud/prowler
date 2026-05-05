import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: vi.fn(async () => ({
    Accept: "application/vnd.api+json",
    Authorization: "Bearer test-token",
    "Content-Type": "application/vnd.api+json",
  })),
}));

import { listAlertRecipients } from "./recipients";

const captureFetchArgs = (status: number, body: unknown) => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchMock = vi.fn(async (url: RequestInfo, init?: RequestInit) => {
    calls.push({ url: url.toString(), init: init ?? {} });
    return new Response(body === null ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/vnd.api+json" },
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

describe("listAlertRecipients", () => {
  it("returns a controlled error without fetching when alerts are disabled", async () => {
    process.env.NEXT_PUBLIC_IS_CLOUD_ENV = "false";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await listAlertRecipients();

    expect(result.ok).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns the parsed list payload", async () => {
    const calls = captureFetchArgs(200, {
      data: [
        {
          id: "1",
          type: "alert-recipients",
          attributes: { email: "a@b.test", status: "pending" },
        },
      ],
      meta: { pagination: { count: 1, page: 1, pages: 1 } },
    });
    const result = await listAlertRecipients(
      new URLSearchParams("filter[status]=pending"),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.data).toHaveLength(1);
      expect(result.data.data[0].attributes.email).toBe("a@b.test");
    }
    expect(calls[0].url).toContain("filter%5Bstatus%5D=pending");
  });
});
