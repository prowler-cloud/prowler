import { describe, expect, it } from "vitest";

import {
  adaptFindingGroupResourcesResponse,
  adaptFindingGroupsResponse,
} from "./finding-groups.adapter";

// ---------------------------------------------------------------------------
// Fix 1: adaptFindingGroupsResponse — unknown + type guard
// ---------------------------------------------------------------------------

describe("adaptFindingGroupsResponse — malformed input", () => {
  it("should return [] when apiResponse is null", () => {
    // Given
    const input = null;

    // When
    const result = adaptFindingGroupsResponse(input);

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when apiResponse has no data property", () => {
    // Given
    const input = { meta: { total: 0 } };

    // When
    const result = adaptFindingGroupsResponse(input);

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when data is not an array", () => {
    // Given
    const input = { data: "not-an-array" };

    // When
    const result = adaptFindingGroupsResponse(input);

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when data is null", () => {
    // Given
    const input = { data: null };

    // When
    const result = adaptFindingGroupsResponse(input);

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when apiResponse is undefined", () => {
    // Given
    const input = undefined;

    // When
    const result = adaptFindingGroupsResponse(input);

    // Then
    expect(result).toEqual([]);
  });

  it("should return mapped rows for valid data", () => {
    // Given
    const input = {
      data: [
        {
          id: "group-1",
          type: "finding-groups",
          attributes: {
            check_id: "s3_bucket_public_access",
            check_title: "S3 Bucket Public Access",
            check_description: null,
            severity: "critical",
            status: "FAIL",
            impacted_providers: ["aws"],
            resources_total: 5,
            resources_fail: 3,
            pass_count: 2,
            fail_count: 3,
            muted_count: 0,
            new_count: 1,
            changed_count: 0,
            first_seen_at: null,
            last_seen_at: "2024-01-01T00:00:00Z",
            failing_since: null,
          },
        },
      ],
    };

    // When
    const result = adaptFindingGroupsResponse(input);

    // Then
    expect(result).toHaveLength(1);
    expect(result[0].checkId).toBe("s3_bucket_public_access");
    expect(result[0].checkTitle).toBe("S3 Bucket Public Access");
  });
});

// ---------------------------------------------------------------------------
// Fix 1: adaptFindingGroupResourcesResponse — unknown + type guard
// ---------------------------------------------------------------------------

describe("adaptFindingGroupResourcesResponse — malformed input", () => {
  it("should return [] when apiResponse is null", () => {
    // Given/When
    const result = adaptFindingGroupResourcesResponse(null, "check-1");

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when apiResponse has no data property", () => {
    // Given/When
    const result = adaptFindingGroupResourcesResponse({ meta: {} }, "check-1");

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when data is not an array", () => {
    // Given/When
    const result = adaptFindingGroupResourcesResponse({ data: {} }, "check-1");

    // Then
    expect(result).toEqual([]);
  });

  it("should return [] when apiResponse is undefined", () => {
    // Given/When
    const result = adaptFindingGroupResourcesResponse(undefined, "check-1");

    // Then
    expect(result).toEqual([]);
  });

  it("should return mapped rows for valid data", () => {
    // Given
    const input = {
      data: [
        {
          id: "resource-row-1",
          type: "finding-group-resources",
          attributes: {
            finding_id: "real-finding-uuid",
            resource: {
              uid: "arn:aws:s3:::my-bucket",
              name: "my-bucket",
              service: "s3",
              region: "us-east-1",
              type: "Bucket",
              resource_group: "default",
            },
            provider: {
              type: "aws",
              uid: "123456789",
              alias: "production",
            },
            status: "FAIL",
            delta: "new",
            severity: "critical",
            first_seen_at: null,
            last_seen_at: "2024-01-01T00:00:00Z",
          },
        },
      ],
    };

    // When
    const result = adaptFindingGroupResourcesResponse(input, "s3_check");

    // Then
    expect(result).toHaveLength(1);
    expect(result[0].findingId).toBe("real-finding-uuid");
    expect(result[0].checkId).toBe("s3_check");
    expect(result[0].resourceName).toBe("my-bucket");
    expect(result[0].delta).toBe("new");
  });
});
