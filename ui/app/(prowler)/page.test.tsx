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

  it("uses the responsive container breakpoint for the primary metric row", () => {
    // Given
    const metricRowClassName = source.match(
      /<div className="([^"]+)">\s*<Suspense fallback={<ThreatScoreSkeleton \/>}>/,
    )?.[1];

    // When
    const metricRowClasses = metricRowClassName?.split(" ") ?? [];

    // Then
    expect(metricRowClassName).toBeDefined();
    expect(metricRowClasses.sort()).toEqual(
      [
        "flex",
        "flex-col",
        "gap-6",
        "lg:flex-row",
        "lg:flex-wrap",
        "lg:items-stretch",
      ].sort(),
    );
  });

  it("keeps findings cards fluid below the desktop row breakpoint", () => {
    // Given
    const statusChartSource = readFileSync(
      path.join(
        currentDir,
        "_overview/status-chart/_components/status-chart.tsx",
      ),
      "utf8",
    );
    const statusChartSkeletonSource = readFileSync(
      path.join(
        currentDir,
        "_overview/status-chart/_components/status-chart.skeleton.tsx",
      ),
      "utf8",
    );
    const riskSeveritySource = readFileSync(
      path.join(
        currentDir,
        "_overview/risk-severity/_components/risk-severity-chart.tsx",
      ),
      "utf8",
    );
    const riskSeveritySkeletonSource = readFileSync(
      path.join(
        currentDir,
        "_overview/risk-severity/_components/risk-severity-chart.skeleton.tsx",
      ),
      "utf8",
    );

    // When
    const cardClassLists = [
      getBaseCardClasses(statusChartSource),
      getBaseCardClasses(statusChartSkeletonSource),
      getBaseCardClasses(riskSeveritySource),
      getBaseCardClasses(riskSeveritySkeletonSource),
    ];

    // Then
    cardClassLists.forEach((cardClasses) => {
      expect(cardClasses).toEqual(
        expect.arrayContaining([
          "w-full",
          "min-w-0",
          "flex-1",
          "lg:w-auto",
          "lg:min-w-[485px]",
        ]),
      );
      const widthClasses = cardClasses.filter((className) =>
        className.includes("w-"),
      );

      expect(widthClasses.sort()).toEqual(
        ["w-full", "min-w-0", "lg:w-auto", "lg:min-w-[485px]"].sort(),
      );
      expect(
        cardClasses.some((className) => className.startsWith("min-[")),
      ).toBe(false);
    });
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
