import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiErrorMock,
  handleApiResponseMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiErrorMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: getAuthHeadersMock,
  getErrorMessage: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

import { listAlertRecipients } from "./recipients";

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ data: [] }), {
      status: 200,
      headers: { "Content-Type": "application/vnd.api+json" },
    }),
  );
  getAuthHeadersMock.mockResolvedValue({
    Accept: "application/vnd.api+json",
    Authorization: "Bearer test-token",
  });
  handleApiResponseMock.mockResolvedValue({ data: [] });
  handleApiErrorMock.mockReturnValue({ error: "Unexpected error." });
});

describe("listAlertRecipients", () => {
  it("returns whatever handleApiResponse returns", async () => {
    handleApiResponseMock.mockResolvedValue({
      data: [
        {
          id: "1",
          type: "alert-recipients",
          attributes: { email: "a@b.test", status: "pending" },
        },
      ],
      meta: { pagination: { count: 1, page: 1, pages: 1 } },
    });
    const result = await listAlertRecipients({
      "filter[status]": "pending",
    });
    expect(result.data).toHaveLength(1);
    expect(result.data[0].attributes.email).toBe("a@b.test");
  });

  it("forwards searchParams as query string", async () => {
    await listAlertRecipients({ "filter[status]": "pending" });
    const [url] = fetchMock.mock.calls.at(-1) ?? [""];
    expect(String(url)).toContain("filter%5Bstatus%5D=pending");
  });
});
