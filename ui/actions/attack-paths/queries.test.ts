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
  executeCustomQuery,
  executeQuery,
  getCartographySchema,
} from "./queries";

describe("executeQuery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("returns a friendly message when API response handling throws", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(null, {
        status: 500,
      }),
    );
    handleApiResponseMock.mockRejectedValue(
      new Error("Server error (500): backend database unavailable"),
    );

    // When
    const result = await executeQuery(
      "550e8400-e29b-41d4-a716-446655440000",
      "aws-iam-statements-allow-all-actions",
    );

    // Then
    expect(handleApiResponseMock).toHaveBeenCalledTimes(1);
    expect(result).toEqual({
      error:
        "Server is temporarily unavailable. Please try again in a few minutes.",
      status: 503,
    });
  });

  it("returns undefined and skips fetch for invalid scan ids", async () => {
    // When
    const result = await executeQuery(
      "not-a-uuid",
      "aws-iam-statements-allow-all-actions",
    );

    // Then
    expect(result).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(handleApiResponseMock).not.toHaveBeenCalled();
  });
});

describe("executeCustomQuery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({
      data: {
        type: "attack-paths-query-run-requests",
        id: null,
        attributes: {
          nodes: [],
          relationships: [],
        },
      },
    });
  });

  it("posts the custom query to the dedicated endpoint", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));

    // When
    await executeCustomQuery(
      "550e8400-e29b-41d4-a716-446655440000",
      "MATCH (n) RETURN n LIMIT 10",
    );

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/attack-paths-scans/550e8400-e29b-41d4-a716-446655440000/queries/custom",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          data: {
            type: "attack-paths-custom-query-run-requests",
            attributes: {
              query: "MATCH (n) RETURN n LIMIT 10",
            },
          },
        }),
      }),
    );
  });

  it("rejects empty custom queries before calling the API", async () => {
    // When
    const result = await executeCustomQuery(
      "550e8400-e29b-41d4-a716-446655440000",
      "   ",
    );

    // Then
    expect(result).toEqual({
      error: "Custom query cannot be empty",
      status: 400,
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(handleApiResponseMock).not.toHaveBeenCalled();
  });

  it("rejects custom queries longer than 10000 characters before calling the API", async () => {
    // When
    const result = await executeCustomQuery(
      "550e8400-e29b-41d4-a716-446655440000",
      "x".repeat(10001),
    );

    // Then
    expect(result).toEqual({
      error: "Custom query must be 10000 characters or fewer",
      status: 400,
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(handleApiResponseMock).not.toHaveBeenCalled();
  });

  it("rejects custom queries with write operations before calling the API", async () => {
    // When
    const result = await executeCustomQuery(
      "550e8400-e29b-41d4-a716-446655440000",
      "MATCH (n) SET n.name = 'updated' RETURN n",
    );

    // Then
    expect(result).toEqual({
      error: "Only read-only queries are allowed",
      status: 400,
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(handleApiResponseMock).not.toHaveBeenCalled();
  });
});

describe("getCartographySchema", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("fetches the schema metadata for the selected scan", async () => {
    // Given
    const apiResponse = {
      data: {
        type: "attack-paths-cartography-schemas",
        id: "aws-0.129.0",
        attributes: {
          id: "aws-0.129.0",
          provider: "aws",
          cartography_version: "0.129.0",
          schema_url:
            "https://github.com/cartography-cncf/cartography/blob/0.129.0/docs/root/modules/aws/schema.md",
          raw_schema_url:
            "https://raw.githubusercontent.com/cartography-cncf/cartography/refs/tags/0.129.0/docs/root/modules/aws/schema.md",
        },
      },
    };
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
    handleApiResponseMock.mockResolvedValue(apiResponse);

    // When
    const result = await getCartographySchema(
      "550e8400-e29b-41d4-a716-446655440000",
    );

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/attack-paths-scans/550e8400-e29b-41d4-a716-446655440000/schema",
      expect.objectContaining({
        method: "GET",
      }),
    );
    expect(result).toEqual(apiResponse);
  });
});
