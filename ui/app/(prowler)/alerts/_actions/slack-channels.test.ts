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

import { getAlertSlackChannels } from "./slack-channels";

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

describe("getAlertSlackChannels", () => {
  it("requests a page large enough for the whole eligible pool", async () => {
    await getAlertSlackChannels();
    const [url] = fetchMock.mock.calls.at(-1) ?? [""];
    expect(String(url)).toContain("page%5Bsize%5D=100");
  });

  it("returns whatever handleApiResponse returns", async () => {
    handleApiResponseMock.mockResolvedValue({
      data: [
        {
          id: "C1",
          type: "alert-slack-channels",
          attributes: { name: "#security" },
        },
      ],
    });
    const result = await getAlertSlackChannels();
    expect(result.data).toHaveLength(1);
    expect(result.data[0].attributes.name).toBe("#security");
  });
});
