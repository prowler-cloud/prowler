import { describe, expect, it } from "vitest";

import { copyAttributionParams, extractUtmParams } from "./utm";

describe("extractUtmParams", () => {
  it("captures every utm_* param when utm_source is present", () => {
    // Given
    const params = new URLSearchParams(
      "utm_source=blackhat&utm_medium=conference&utm_content=badge&foo=bar",
    );

    // When / Then
    expect(extractUtmParams(params)).toEqual({
      utm_source: "blackhat",
      utm_medium: "conference",
      utm_content: "badge",
    });
  });

  it("returns empty for utm params without attribution source", () => {
    // Given / When / Then
    expect(extractUtmParams({ utm_content: "alerts" })).toEqual({});
  });

  it("captures promo_code on its own as valid attribution", () => {
    // Given
    const params = new URLSearchParams(
      "promo_code=95b2c481-f9d5-4fc2-bc34-0b542e25f00b",
    );

    // When / Then
    expect(extractUtmParams(params)).toEqual({
      promo_code: "95b2c481-f9d5-4fc2-bc34-0b542e25f00b",
    });
  });

  it("lets promo_code carry sourceless utm params", () => {
    // Given
    const params = new URLSearchParams("utm_content=badge&promo_code=abc");

    // When / Then
    expect(extractUtmParams(params)).toEqual({
      utm_content: "badge",
      promo_code: "abc",
    });
  });
});

describe("copyAttributionParams", () => {
  it("copies attribution params and drops unrelated params", () => {
    // Given
    const source = new URLSearchParams(
      "promo_code=black-hat-2026&utm_source=blackhat&foo=bar",
    );
    const target = new URLSearchParams("callbackUrl=/");

    // When
    copyAttributionParams(source, target);

    // Then
    expect(target.get("callbackUrl")).toBe("/");
    expect(target.get("promo_code")).toBe("black-hat-2026");
    expect(target.get("utm_source")).toBe("blackhat");
    expect(target.get("foo")).toBeNull();
  });
});
