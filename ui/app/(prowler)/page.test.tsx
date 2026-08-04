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

  it("keeps the primary metric row horizontal and wrapping at every width", () => {
    expect(source).toMatch(
      /className="flex flex-col gap-6 min-\[485px\]:flex-row min-\[485px\]:flex-wrap min-\[485px\]:items-stretch"/,
    );
  });

  it("keeps findings metric cards at their minimum readable width", () => {
    const statusChartSource = readFileSync(
      path.join(
        currentDir,
        "_overview/status-chart/_components/status-chart.tsx",
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

    expect(statusChartSource).toMatch(/min-\[485px\]:min-w-\[485px\]/);
    expect(riskSeveritySource).toMatch(/min-\[485px\]:min-w-\[485px\]/);
    expect(statusChartSource).toMatch(/min-\[485px\]:w-auto/);
    expect(riskSeveritySource).toMatch(/min-\[485px\]:w-auto/);
  });
});
