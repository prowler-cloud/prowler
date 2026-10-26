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

import {
  getIssue,
  getIssueFindings,
  getIssues,
  getIssuesOverview,
} from "./issues";

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

  it("loads folded findings from the exact scan and maps all associated resources", async () => {
    // Given
    handleApiResponseMock.mockResolvedValue({
      data: [
        {
          id: "finding-1",
          attributes: {
            check_id: "ssh",
            severity: "critical",
            check_metadata: { checktitle: "SSH exposed" },
          },
          relationships: { resources: { data: [{ id: "r1" }, { id: "r2" }] } },
        },
      ],
      included: [
        { type: "resources", id: "r1", attributes: { uid: "instance" } },
        { type: "resources", id: "r2", attributes: { uid: "security-group" } },
      ],
    });

    // When
    const findings = await getIssueFindings("issue-scan", ["finding-uid"]);

    // Then
    const url = new URL(fetchMock.mock.calls[0][0]);
    expect(url.pathname).toBe("/api/v1/findings");
    expect(url.searchParams.get("filter[scan]")).toBe("issue-scan");
    expect(url.searchParams.get("filter[uid__in]")).toBe("finding-uid");
    expect(url.searchParams.get("include")).toBe("resources");
    expect(findings).toEqual(
      ["instance", "security-group"].map((resourceUid) => ({
        id: "finding-1",
        checkId: "ssh",
        checkTitle: "SSH exposed",
        severity: "critical",
        resourceUid,
      })),
    );
  });

  it("caps unique finding UIDs at 50", async () => {
    // Given
    handleApiResponseMock.mockResolvedValue({ data: [] });
    const uids = Array.from({ length: 60 }, (_, index) => `uid-${index}`);
    // When
    await getIssueFindings("scan-1", [uids[0], ...uids]);
    // Then
    const url = new URL(fetchMock.mock.calls[0][0]);
    expect(url.searchParams.get("filter[uid__in]")).toBe(
      uids.slice(0, 50).join(","),
    );
    expect(url.searchParams.get("page[size]")).toBe("50");
  });

  it("does not issue an unfiltered request for an empty list or missing scan", async () => {
    await expect(getIssueFindings("scan-1", [])).resolves.toEqual([]);
    await expect(getIssueFindings("", ["uid-1"])).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("distinguishes API failures from an empty set of findings", async () => {
    await expect(
      getIssueFindings("scan-1", ["uid-1"]),
    ).resolves.toBeUndefined();
    handleApiResponseMock.mockResolvedValueOnce({
      errors: [{ status: "403" }],
    });
    await expect(
      getIssueFindings("scan-1", ["uid-1"]),
    ).resolves.toBeUndefined();
  });
});
