import { describe, expect, it } from "vitest";

import { getRegionFlag } from "./region-flags";

// ---------------------------------------------------------------------------
// Fix 6: Taiwan (asia-east1) mapped correctly vs Hong Kong (asia-east2)
// ---------------------------------------------------------------------------

describe("getRegionFlag — Taiwan vs Hong Kong disambiguation", () => {
  it("should return 🇹🇼 for GCP asia-east1 (Taiwan)", () => {
    // Given/When
    const result = getRegionFlag("asia-east1");

    // Then
    expect(result).toBe("🇹🇼");
  });

  it("should return 🇭🇰 for GCP asia-east2 (Hong Kong)", () => {
    // Given/When
    const result = getRegionFlag("asia-east2");

    // Then
    expect(result).toBe("🇭🇰");
  });

  it("should return 🇭🇰 for regions containing 'hongkong'", () => {
    // Given/When
    const result = getRegionFlag("hongkong");

    // Then
    expect(result).toBe("🇭🇰");
  });

  it("should NOT return 🇭🇰 for asia-east1", () => {
    // Given/When
    const result = getRegionFlag("asia-east1");

    // Then — confirm it's not Hong Kong flag
    expect(result).not.toBe("🇭🇰");
  });
});

describe("getRegionFlag — existing regions not broken", () => {
  it("should return 🇺🇸 for us-east-1 (AWS)", () => {
    expect(getRegionFlag("us-east-1")).toBe("🇺🇸");
  });

  it("should return 🇪🇺 for eu-west-1 (AWS)", () => {
    expect(getRegionFlag("eu-west-1")).toBe("🇪🇺");
  });

  it("should return 🇯🇵 for ap-northeast-1 (Japan)", () => {
    expect(getRegionFlag("ap-northeast-1")).toBe("🇯🇵");
  });

  it("should return 🇦🇺 for ap-southeast-2 (Australia)", () => {
    expect(getRegionFlag("ap-southeast-2")).toBe("🇦🇺");
  });

  it("should return 🇸🇬 for ap-southeast-1 (Singapore)", () => {
    expect(getRegionFlag("ap-southeast-1")).toBe("🇸🇬");
  });

  it("should return empty string for '-' (unknown/no region)", () => {
    expect(getRegionFlag("-")).toBe("");
  });

  it("should return empty string for empty string", () => {
    expect(getRegionFlag("")).toBe("");
  });
});
