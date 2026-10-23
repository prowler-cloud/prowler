import { afterEach, describe, expect, it, vi } from "vitest";

import { readBoolEnv, readEnv, readOptOutEnv } from "./runtime-env";

describe("readEnv", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns the primary value when it is set", () => {
    // Given
    vi.stubEnv("UI_API_BASE_URL", "https://primary.example.com");

    // When / Then
    expect(readEnv("UI_API_BASE_URL")).toBe("https://primary.example.com");
  });

  it("returns null when the primary is unset and no legacy is given", () => {
    // Given
    vi.stubEnv("UI_API_BASE_URL", undefined);

    // When / Then
    expect(readEnv("UI_API_BASE_URL")).toBeNull();
  });

  it("treats an empty or whitespace-only primary as unset", () => {
    // Given
    vi.stubEnv("UI_API_BASE_URL", "   ");

    // When / Then
    expect(readEnv("UI_API_BASE_URL")).toBeNull();
  });

  it("falls back to the legacy var when the primary is unset", () => {
    // Given
    vi.stubEnv("UI_API_BASE_URL", undefined);
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "https://legacy.example.com");

    // When / Then
    expect(readEnv("UI_API_BASE_URL", "NEXT_PUBLIC_API_BASE_URL")).toBe(
      "https://legacy.example.com",
    );
  });

  it("falls back to the legacy var when the primary is empty", () => {
    // Given
    vi.stubEnv("UI_API_BASE_URL", "");
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "https://legacy.example.com");

    // When / Then
    expect(readEnv("UI_API_BASE_URL", "NEXT_PUBLIC_API_BASE_URL")).toBe(
      "https://legacy.example.com",
    );
  });

  it("prefers the primary over the legacy when both are set", () => {
    // Given
    vi.stubEnv("UI_API_BASE_URL", "https://primary.example.com");
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "https://legacy.example.com");

    // When / Then
    expect(readEnv("UI_API_BASE_URL", "NEXT_PUBLIC_API_BASE_URL")).toBe(
      "https://primary.example.com",
    );
  });

  it("returns null when neither the primary nor the legacy is set", () => {
    // Given
    vi.stubEnv("UI_API_BASE_URL", undefined);
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", undefined);

    // When / Then
    expect(readEnv("UI_API_BASE_URL", "NEXT_PUBLIC_API_BASE_URL")).toBeNull();
  });
});

describe("readBoolEnv", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('is true only for the exact string "true"', () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLED", "true");

    // When / Then
    expect(readBoolEnv("UI_SENTRY_ENABLED")).toBe(true);
  });

  it("trims surrounding whitespace before comparing", () => {
    // Given - clean() does not trim a non-empty value, so readBoolEnv must
    vi.stubEnv("UI_SENTRY_ENABLED", "  true  ");

    // When / Then
    expect(readBoolEnv("UI_SENTRY_ENABLED")).toBe(true);
  });

  it("is false when unset", () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLED", undefined);

    // When / Then
    expect(readBoolEnv("UI_SENTRY_ENABLED")).toBe(false);
  });

  it('is false for "false"', () => {
    // Given
    vi.stubEnv("UI_SENTRY_ENABLED", "false");

    // When / Then
    expect(readBoolEnv("UI_SENTRY_ENABLED")).toBe(false);
  });

  it('is false for other truthy-looking values ("TRUE", "1", "yes")', () => {
    for (const value of ["TRUE", "1", "yes"]) {
      // Given
      vi.stubEnv("UI_SENTRY_ENABLED", value);

      // When / Then
      expect(readBoolEnv("UI_SENTRY_ENABLED")).toBe(false);
    }
  });
});

describe("readOptOutEnv", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("is true when unset", () => {
    vi.stubEnv("UI_SELF_REGISTRATION_ENABLED", undefined);

    expect(readOptOutEnv("UI_SELF_REGISTRATION_ENABLED")).toBe(true);
  });

  it('is false for "false" in any case, whitespace trimmed', () => {
    for (const value of ["false", " False ", "FALSE"]) {
      vi.stubEnv("UI_SELF_REGISTRATION_ENABLED", value);
      expect(readOptOutEnv("UI_SELF_REGISTRATION_ENABLED")).toBe(false);
    }
  });

  it('stays true for any other value ("true", "0", "no")', () => {
    for (const value of ["true", "0", "no"]) {
      vi.stubEnv("UI_SELF_REGISTRATION_ENABLED", value);
      expect(readOptOutEnv("UI_SELF_REGISTRATION_ENABLED")).toBe(true);
    }
  });
});
