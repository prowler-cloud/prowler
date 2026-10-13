import { describe, expect, it } from "vitest";

import {
  findProviderIdForTarget,
  getPartialScanErrorMessage,
  isPartialScanAvailable,
  isPartialScanTarget,
  PARTIAL_SCAN_LAUNCH_ERROR,
} from "./partial-scans";

describe("isPartialScanAvailable", () => {
  it("needs both Prowler Cloud and the manage_scans permission", () => {
    expect(
      isPartialScanAvailable({ cloudEnabled: true, canManageScans: true }),
    ).toBe(true);
    expect(
      isPartialScanAvailable({ cloudEnabled: false, canManageScans: true }),
    ).toBe(false);
    expect(
      isPartialScanAvailable({ cloudEnabled: true, canManageScans: false }),
    ).toBe(false);
  });
});

describe("isPartialScanTarget", () => {
  it("accepts a resource uid with a provider id", () => {
    expect(
      isPartialScanTarget({
        providerId: "provider-1",
        resourceUid: "arn:aws:s3:::bucket",
        resourceName: "bucket",
      }),
    ).toBe(true);
  });

  it("accepts a resource uid with a provider uid and type", () => {
    expect(
      isPartialScanTarget({
        providerUid: "123456789012",
        providerType: "aws",
        resourceUid: "arn:aws:s3:::bucket",
        resourceName: "bucket",
      }),
    ).toBe(true);
  });

  it("rejects placeholder or missing identifiers", () => {
    // Adapters fill unknown values with "-", which is not a real uid.
    expect(
      isPartialScanTarget({
        providerId: "provider-1",
        resourceUid: "-",
        resourceName: "bucket",
      }),
    ).toBe(false);
    expect(
      isPartialScanTarget({
        providerUid: "",
        providerType: "aws",
        resourceUid: "arn:aws:s3:::bucket",
      }),
    ).toBe(false);
    expect(isPartialScanTarget(null)).toBe(false);
  });
});

describe("findProviderIdForTarget", () => {
  const providers = [
    { id: "aws-1", attributes: { uid: "123456789012", provider: "aws" } },
    { id: "gcp-1", attributes: { uid: "123456789012", provider: "gcp" } },
  ] as never[];

  it("matches on uid and provider type together", () => {
    expect(
      findProviderIdForTarget(providers, {
        providerUid: "123456789012",
        providerType: "gcp",
      }),
    ).toBe("gcp-1");
  });

  it("returns undefined when nothing matches", () => {
    expect(
      findProviderIdForTarget(providers, {
        providerUid: "000000000000",
        providerType: "aws",
      }),
    ).toBeUndefined();
  });
});

describe("getPartialScanErrorMessage", () => {
  it("returns null for a created scan", () => {
    expect(getPartialScanErrorMessage({ data: { id: "scan-1" } })).toBeNull();
  });

  it("surfaces the API detail for a refused re-check", () => {
    expect(
      getPartialScanErrorMessage({
        error: "A scan is already running for this provider.",
        status: 409,
      }),
    ).toBe("A scan is already running for this provider.");
  });

  it("falls back to a generic message when the error carries no detail", () => {
    expect(getPartialScanErrorMessage({ status: 500 })).toBe(
      PARTIAL_SCAN_LAUNCH_ERROR,
    );
  });
});
