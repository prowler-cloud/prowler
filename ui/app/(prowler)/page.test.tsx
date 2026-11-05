import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Overview page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(filePath, "utf8");

  const getBaseCardClasses = (componentSource: string) => {
    const className = componentSource.match(
      /<Card\s+variant="base"\s+className="([^"]+)"/,
    )?.[1];

    expect(className).toBeDefined();

    return className?.split(" ") ?? [];
  };

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

  it("keeps findings skeletons aligned with their loaded cards", () => {
    // Given
    const sourcePairs = [
      [
        "_overview/status-chart/_components/status-chart.tsx",
        "_overview/status-chart/_components/status-chart.skeleton.tsx",
      ],
      [
        "_overview/risk-severity/_components/risk-severity-chart.tsx",
        "_overview/risk-severity/_components/risk-severity-chart.skeleton.tsx",
      ],
    ];

    // When / Then
    sourcePairs.forEach(([componentPath, skeletonPath]) => {
      const componentClasses = getBaseCardClasses(
        readFileSync(path.join(currentDir, componentPath), "utf8"),
      );
      const skeletonClasses = getBaseCardClasses(
        readFileSync(path.join(currentDir, skeletonPath), "utf8"),
      );

      expect(skeletonClasses).toEqual(componentClasses);
    });
  });
});
