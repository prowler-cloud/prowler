import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Overview page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(filePath, "utf8");

  it("renders the overview banners before the provider filters", () => {
    // Given
    const firstBannerPosition = source.indexOf("<OverviewBanner");
    const firstProviderFilterPosition = source.indexOf(
      "<ProviderAccountSelectors",
    );

    // When
    const bannersRenderBeforeFilters =
      firstBannerPosition < firstProviderFilterPosition;

    // Then
    expect(firstBannerPosition).toBeGreaterThan(-1);
    expect(firstProviderFilterPosition).toBeGreaterThan(-1);
    expect(bannersRenderBeforeFilters).toBe(true);
  });
});
