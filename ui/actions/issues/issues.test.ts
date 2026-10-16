import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

import { getIssue, getIssues, getIssuesOverview } from "./issues";

describe("issues actions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    fetchMock.mockResolvedValue(new Response("", { status: 500 }));
    // handleApiResponse rejects on a 5xx; the action must catch it.
    handleApiResponseMock.mockRejectedValue(new Error("Server error"));
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("getIssues returns undefined when the API answers 500", async () => {
    await expect(getIssues()).resolves.toBeUndefined();
  });

  it("getIssue returns undefined when the API answers 500", async () => {
    await expect(getIssue("issue-1")).resolves.toBeUndefined();
  });

  it("getIssuesOverview returns undefined when the API answers 500", async () => {
    await expect(getIssuesOverview()).resolves.toBeUndefined();
  });
});
