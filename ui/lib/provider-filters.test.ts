import { describe, expect, it } from "vitest";

import {
  appendSanitizedProviderInFilters,
  appendSanitizedProviderTypeFilters,
} from "./provider-filters";

const PROVIDER_TYPE_IN = "filter[provider_type__in]";
const PROVIDER_IN = "filter[provider__in]";

const makeUrl = () => new URL("https://api.test/v1/providers");

describe("appendSanitizedProviderTypeFilters", () => {
  it("forwards a known provider type unchanged", () => {
    // Given
    const url = makeUrl();
    // When
    appendSanitizedProviderTypeFilters(url, { [PROVIDER_TYPE_IN]: "aws" });
    // Then
    expect(url.searchParams.get(PROVIDER_TYPE_IN)).toBe("aws");
  });

  it("forwards a dynamic provider type verbatim (not dropped or replaced)", () => {
    // Given
    const url = makeUrl();
    // When
    appendSanitizedProviderTypeFilters(url, { [PROVIDER_TYPE_IN]: "template" });
    // Then
    expect(url.searchParams.get(PROVIDER_TYPE_IN)).toBe("template");
  });

  it("injects no provider-type allowlist when nothing is selected", () => {
    // Given
    const url = makeUrl();
    // When
    appendSanitizedProviderTypeFilters(url, {});
    // Then
    expect(url.searchParams.has(PROVIDER_TYPE_IN)).toBe(false);
  });

  it("keeps a mixed known + dynamic selection intact", () => {
    // Given
    const url = makeUrl();
    // When
    appendSanitizedProviderTypeFilters(url, {
      [PROVIDER_TYPE_IN]: "aws,template",
    });
    // Then
    expect(url.searchParams.get(PROVIDER_TYPE_IN)).toBe("aws,template");
  });

  it("excludes the search filter by default", () => {
    // Given
    const url = makeUrl();
    // When
    appendSanitizedProviderTypeFilters(url, {
      "filter[search]": "prod",
      [PROVIDER_TYPE_IN]: "template",
    });
    // Then
    expect(url.searchParams.has("filter[search]")).toBe(false);
    expect(url.searchParams.get(PROVIDER_TYPE_IN)).toBe("template");
  });
});

describe("appendSanitizedProviderInFilters", () => {
  it("forwards a dynamic provider id verbatim", () => {
    // Given
    const url = makeUrl();
    // When
    appendSanitizedProviderInFilters(url, { [PROVIDER_IN]: "provider-uuid" });
    // Then
    expect(url.searchParams.get(PROVIDER_IN)).toBe("provider-uuid");
  });

  it("injects no provider allowlist when nothing is selected", () => {
    // Given
    const url = makeUrl();
    // When
    appendSanitizedProviderInFilters(url, {});
    // Then
    expect(url.searchParams.has(PROVIDER_IN)).toBe(false);
  });
});
