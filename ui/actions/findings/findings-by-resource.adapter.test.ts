import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Hoist mocks BEFORE imports that transitively pull next-auth
// ---------------------------------------------------------------------------

const { createDictMock } = vi.hoisted(() => ({
  createDictMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  createDict: createDictMock,
  apiBaseUrl: "https://api.example.com",
  getAuthHeaders: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import { adaptFindingsByResourceResponse } from "./findings-by-resource.adapter";

// ---------------------------------------------------------------------------
// Fix 1: adaptFindingsByResourceResponse — unknown + type guard
// ---------------------------------------------------------------------------

describe("adaptFindingsByResourceResponse — malformed input", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // createDict returns empty dict by default for most tests
    createDictMock.mockReturnValue({});
  });

  it("should return [] when apiResponse is null", () => {
    // Given/When
    const result = adaptFindingsByResourceResponse(null);

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when apiResponse is undefined", () => {
    // Given/When
    const result = adaptFindingsByResourceResponse(undefined);

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when apiResponse has no data property", () => {
    // Given/When
    const result = adaptFindingsByResourceResponse({ meta: {} });

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when data is not an array", () => {
    // Given/When
    const result = adaptFindingsByResourceResponse({ data: "bad" });

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when data is an empty array", () => {
    // Given/When
    const result = adaptFindingsByResourceResponse({ data: [], included: [] });

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when data is a number", () => {
    // Given/When
    const result = adaptFindingsByResourceResponse({ data: 42 });

    // Then
    expect(result).toEqual([]);
  });

  it("should return mapped findings for valid minimal data", () => {
    // Given — minimal valid JSON:API shape
    const input = {
      data: [
        {
          id: "finding-1",
          attributes: {
            uid: "uid-1",
            check_id: "s3_check",
            status: "FAIL",
            severity: "critical",
            check_metadata: {
              checktitle: "S3 Check",
            },
          },
          relationships: {
            resources: { data: [] },
            scan: { data: null },
          },
        },
      ],
      included: [],
    };

    // When
    const result = adaptFindingsByResourceResponse(input);

    // Then
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("finding-1");
    expect(result[0].checkId).toBe("s3_check");
  });

  it("should extract resource metadata and details from the included resource", () => {
    // Given — finding with an included resource exposing metadata + details
    createDictMock.mockImplementation((type: string) =>
      type === "resources"
        ? {
            "resource-1": {
              id: "resource-1",
              attributes: {
                uid: "image:python:3.12",
                name: "python",
                type: "Python",
                details: "Python 3.12 base image",
                metadata: '{"PkgName":"requests","Versions":["2.0"]}',
              },
            },
          }
        : {},
    );

    const input = {
      data: {
        id: "finding-1",
        attributes: {
          uid: "uid-1",
          check_id: "image_vulnerability",
          status: "FAIL",
          severity: "critical",
          check_metadata: { checktitle: "Image Vulnerability" },
        },
        relationships: {
          resources: { data: [{ id: "resource-1" }] },
          scan: { data: null },
        },
      },
      included: [],
    };

    // When
    const result = adaptFindingsByResourceResponse(input);

    // Then
    expect(result).toHaveLength(1);
    expect(result[0].resourceDetails).toBe("Python 3.12 base image");
    expect(result[0].resourceMetadata).toBe(
      '{"PkgName":"requests","Versions":["2.0"]}',
    );
  });

  it("should default resource metadata and details to null when absent", () => {
    // Given — valid finding without an included resource
    const input = {
      data: [
        {
          id: "finding-1",
          attributes: {
            uid: "uid-1",
            check_id: "s3_check",
            status: "FAIL",
            severity: "critical",
            check_metadata: { checktitle: "S3 Check" },
          },
          relationships: {
            resources: { data: [] },
            scan: { data: null },
          },
        },
      ],
      included: [],
    };

    // When
    const result = adaptFindingsByResourceResponse(input);

    // Then
    expect(result[0].resourceDetails).toBeNull();
    expect(result[0].resourceMetadata).toBeNull();
  });

  it("should normalize a single finding response into a one-item drawer array", () => {
    // Given — getFindingById returns a single JSON:API resource object
    const input = {
      data: {
        id: "finding-1",
        attributes: {
          uid: "uid-1",
          check_id: "s3_check",
          status: "FAIL",
          severity: "critical",
          check_metadata: {
            checktitle: "S3 Check",
          },
        },
        relationships: {
          resources: { data: [] },
          scan: { data: null },
        },
      },
      included: [],
    };

    // When
    const result = adaptFindingsByResourceResponse(input);

    // Then
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("finding-1");
    expect(result[0].checkTitle).toBe("S3 Check");
  });
});
