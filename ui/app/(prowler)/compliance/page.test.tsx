import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Compliance overview page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "page.tsx");
  const source = readFileSync(filePath, "utf8");

  it("delegates client-side search to ComplianceOverviewGrid", () => {
    expect(source).toContain("ComplianceOverviewGrid");
    expect(source).not.toContain("filter[search]");
  });

  it("gates the Cross-Provider tab behind Prowler Cloud", () => {
    // OSS must force Per Scan: the tab resolution only honours ?tab= when
    // isCloud() is true, and both per-scan returns render the tab switcher.
    expect(source).toContain("const crossProviderEnabled = isCloud()");
    expect(source).toContain("getComplianceTab(resolvedSearchParams.tab)");
    expect(source.match(/CompliancePageTabs/g)?.length).toBeGreaterThanOrEqual(
      3,
    );
  });

  it("only builds the cross-provider payload when its tab is active", () => {
    const crossProviderBranch = source.indexOf(
      "activeTab === COMPLIANCE_TAB.CROSS_PROVIDER",
    );
    const scansFetch = source.indexOf("await getScans(");
    expect(crossProviderBranch).toBeGreaterThan(-1);
    // The cross-provider branch returns before any per-scan fetch runs.
    expect(crossProviderBranch).toBeLessThan(scansFetch);
  });
});
