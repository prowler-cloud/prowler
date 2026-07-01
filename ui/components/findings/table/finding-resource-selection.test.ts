import { describe, expect, it } from "vitest";

import type { FindingResourceRow } from "@/types";

import { canMuteFindingResource } from "./finding-resource-selection";

function makeResource(
  overrides?: Partial<FindingResourceRow>,
): FindingResourceRow {
  return {
    id: "finding-1",
    rowType: "resource",
    findingId: "finding-1",
    checkId: "check-1",
    providerType: "aws",
    providerAlias: "prod",
    providerUid: "123456789012",
    resourceName: "bucket-a",
    resourceType: "Bucket",
    resourceGroup: "bucket-a",
    resourceUid: "arn:aws:s3:::bucket-a",
    service: "s3",
    region: "us-east-1",
    severity: "high",
    status: "FAIL",
    isMuted: false,
    firstSeenAt: null,
    lastSeenAt: null,
    ...overrides,
  };
}

describe("canMuteFindingResource", () => {
  it("should allow muting FAIL resources that are not muted", () => {
    expect(canMuteFindingResource(makeResource())).toBe(true);
  });

  it("should disable muting for PASS resources", () => {
    expect(canMuteFindingResource(makeResource({ status: "PASS" }))).toBe(
      false,
    );
  });

  it("should disable muting for already muted resources", () => {
    expect(canMuteFindingResource(makeResource({ isMuted: true }))).toBe(false);
  });
});
