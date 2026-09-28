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

import { getTasksByIds } from "./tasks";

describe("getTasksByIds", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiErrorMock.mockReturnValue({ error: "Unexpected error" });
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
  });

  it("reads every task in one call, keyed by id, on a single auth read", async () => {
    // Given
    handleApiResponseMock.mockImplementation(async () => ({
      data: { attributes: { state: "executing" } },
    }));

    // When
    const snapshots = await getTasksByIds(["task-a", "task-b"]);

    // Then — one request per task (`TaskFilter` has no id filter), overlapping.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(getAuthHeadersMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "https://api.example.com/api/v1/tasks/task-a",
      "https://api.example.com/api/v1/tasks/task-b",
    ]);
    expect(Object.keys(snapshots)).toEqual(["task-a", "task-b"]);
  });

  it("keeps a failed read to its own task", async () => {
    // Given
    handleApiResponseMock.mockResolvedValue({
      data: { attributes: { state: "completed" } },
    });
    fetchMock
      .mockRejectedValueOnce(new Error("socket hang up"))
      .mockResolvedValueOnce(new Response(null, { status: 200 }));

    // When
    const snapshots = await getTasksByIds(["task-a", "task-b"]);

    // Then
    expect(snapshots["task-a"]).toEqual({ error: "Unexpected error" });
    expect(snapshots["task-b"]).toEqual({
      data: { attributes: { state: "completed" } },
    });
  });

  it("does not reach the API for an empty batch", async () => {
    // When
    const snapshots = await getTasksByIds([]);

    // Then
    expect(snapshots).toEqual({});
    expect(getAuthHeadersMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
