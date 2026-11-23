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
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));

import {
  addIssueNote,
  getIssue,
  getIssueFindings,
  getIssueNotes,
  getIssues,
  getIssuesOverview,
  updateIssueTriage,
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
            uid: "finding-uid",
            check_id: "ssh",
            severity: "critical",
            check_metadata: { checktitle: "SSH exposed" },
            // Nobody has triaged it yet.
            triage_status: null,
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
    expect(url.searchParams.get("fields[findings]")).toContain("triage_status");
    expect(findings).toEqual(
      ["instance", "security-group"].map((resourceUid) => ({
        id: "finding-1",
        uid: "finding-uid",
        checkId: "ssh",
        checkTitle: "SSH exposed",
        severity: "critical",
        triageStatus: "open",
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

  it("triages through the issue's triage, as findings are triaged", async () => {
    // Given
    const response = new Response("{}", { status: 200 });
    fetchMock.mockResolvedValue(response);
    handleApiResponseMock.mockResolvedValue({ data: {} });

    // When
    const result = await updateIssueTriage("issue-1", {
      status: "risk_accepted",
      note: "Static site.",
    });

    // Then
    expect(result).toEqual({ success: true });
    // The list shows each issue's triage status.
    expect(handleApiResponseMock).toHaveBeenCalledWith(response, "/issues");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/api/v1/issues/issue-1/triage");
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body)).toEqual({
      data: {
        type: "issue-triages",
        attributes: { status: "risk_accepted", note: "Static site." },
      },
    });
  });

  it("returns the API's reason when a triage write is refused", async () => {
    handleApiResponseMock.mockResolvedValue({
      error: "You do not have permission.",
      status: 403,
    });

    await expect(addIssueNote("issue-1", "note")).resolves.toEqual({
      error: "You do not have permission.",
      status: 403,
    });
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://api.example.com/api/v1/issues/issue-1/triage/notes",
    );
  });

  it("returns the shared, sanitized message when a triage write fails on the server", async () => {
    // Given: handleApiResponse rejects on a 5xx (see beforeEach)
    handleApiErrorMock.mockReturnValue({ error: "Something went wrong." });

    // When
    const result = await addIssueNote("issue-1", "note");

    // Then
    expect(result).toEqual({ error: "Something went wrong." });
    expect(handleApiErrorMock).toHaveBeenCalledWith(new Error("Server error"));
  });

  it.each([
    {
      operation: "updating triage",
      save: () => updateIssueTriage("issue-1", { status: "risk_accepted" }),
    },
    {
      operation: "adding a note",
      save: () => addIssueNote("issue-1", "Accepted."),
    },
  ])(
    "returns a save error when authentication fails while $operation",
    async ({ save }) => {
      // Given
      getAuthHeadersMock.mockRejectedValue(new Error("Session lookup failed"));
      handleApiErrorMock.mockReturnValue({ error: "Something went wrong." });

      // When / Then
      await expect(save()).resolves.toEqual({ error: "Something went wrong." });
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("names each note's author from the included users", async () => {
    // Given
    handleApiResponseMock.mockResolvedValue({
      data: [
        {
          type: "issue-triage-notes",
          id: "note-1",
          attributes: { body: "Accepted.", inserted_at: "2026-10-20" },
          relationships: { created_by: { data: { type: "users", id: "u1" } } },
        },
        {
          type: "issue-triage-notes",
          id: "note-2",
          attributes: { body: "Orphan.", inserted_at: "2026-10-19" },
          relationships: { created_by: { data: null } },
        },
      ],
      included: [{ type: "users", id: "u1", attributes: { name: "Ana" } }],
    });

    // When
    const notes = await getIssueNotes("issue-1");

    // Then
    const url = new URL(fetchMock.mock.calls[0][0]);
    expect(url.pathname).toBe("/api/v1/issues/issue-1/triage/notes");
    expect(url.searchParams.get("include")).toBe("created_by");
    expect(url.searchParams.get("page[size]")).toBe("100");
    expect(notes).toEqual([
      {
        id: "note-1",
        body: "Accepted.",
        insertedAt: "2026-10-20",
        author: "Ana",
      },
      {
        id: "note-2",
        body: "Orphan.",
        insertedAt: "2026-10-19",
        author: undefined,
      },
    ]);
  });
});
