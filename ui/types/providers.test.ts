import { describe, expect, it } from "vitest";

import {
  getProviderDisplayName,
  humanizeProviderId,
  isConfigurableProvider,
  isKnownProviderType,
} from "./providers";

describe("humanizeProviderId", () => {
  it("capitalizes a single-word id", () => {
    expect(humanizeProviderId("template")).toBe("Template");
  });

  it("splits on hyphens and capitalizes each word", () => {
    expect(humanizeProviderId("local-template")).toBe("Local Template");
  });

  it("splits on underscores", () => {
    expect(humanizeProviderId("foo_bar")).toBe("Foo Bar");
  });

  it("collapses repeated separators and trims empties", () => {
    expect(humanizeProviderId("a--b__c")).toBe("A B C");
  });

  it("returns an empty string for an empty id", () => {
    expect(humanizeProviderId("")).toBe("");
  });
});

describe("getProviderDisplayName", () => {
  it("returns the configured label for a known provider", () => {
    expect(getProviderDisplayName("aws")).toBe("AWS");
    expect(getProviderDisplayName("gcp")).toBe("Google Cloud");
  });

  it("is case-insensitive for known providers", () => {
    expect(getProviderDisplayName("AWS")).toBe("AWS");
  });

  it("humanizes an unknown/dynamic provider id", () => {
    expect(getProviderDisplayName("template")).toBe("Template");
    expect(getProviderDisplayName("local-template")).toBe("Local Template");
  });
});

describe("isKnownProviderType / isConfigurableProvider", () => {
  it("accepts a known provider", () => {
    expect(isKnownProviderType("aws")).toBe(true);
    expect(isConfigurableProvider("aws")).toBe(true);
  });

  it("rejects a dynamic/unknown provider", () => {
    expect(isKnownProviderType("template")).toBe(false);
    expect(isConfigurableProvider("template")).toBe(false);
  });

  it("rejects an empty provider value", () => {
    expect(isKnownProviderType("")).toBe(false);
    expect(isConfigurableProvider("")).toBe(false);
  });
});
