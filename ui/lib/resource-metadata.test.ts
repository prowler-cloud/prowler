import { describe, expect, it } from "vitest";

import { parseMetadata } from "./resource-metadata";

describe("parseMetadata", () => {
  it("should return null for nullish or empty values", () => {
    expect(parseMetadata(null)).toBeNull();
    expect(parseMetadata(undefined)).toBeNull();
    expect(parseMetadata("")).toBeNull();
  });

  it("should parse a JSON object string into an object", () => {
    expect(parseMetadata('{"PkgName":"requests","Versions":["2.0"]}')).toEqual({
      PkgName: "requests",
      Versions: ["2.0"],
    });
  });

  it("should return null when the string is not valid JSON", () => {
    expect(parseMetadata("not-json")).toBeNull();
  });

  it("should return null when the JSON string is not an object", () => {
    expect(parseMetadata("42")).toBeNull();
    expect(parseMetadata('"plain string"')).toBeNull();
  });

  it("should return null when the JSON string is an array", () => {
    expect(parseMetadata("[1,2,3]")).toBeNull();
    expect(parseMetadata("[]")).toBeNull();
    expect(parseMetadata('[{"PkgName":"requests"}]')).toBeNull();
  });

  it("should return null when the value is already an array", () => {
    expect(
      parseMetadata([1, 2, 3] as unknown as Record<string, unknown>),
    ).toBeNull();
  });

  it("should return the object as-is when already an object", () => {
    const metadata = { VulnerabilityID: "CVE-2026-0001" };
    expect(parseMetadata(metadata)).toBe(metadata);
  });
});
