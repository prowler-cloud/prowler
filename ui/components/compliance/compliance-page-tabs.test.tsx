import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("CompliancePageTabs", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const tabsSource = readFileSync(
    path.join(currentDir, "compliance-page-tabs.tsx"),
    "utf8",
  );
  const sharedSource = readFileSync(
    path.join(currentDir, "compliance-page-tabs.shared.ts"),
    "utf8",
  );

  it("declares the two tab keys used across the page", () => {
    expect(sharedSource).toContain("per-scan");
    expect(sharedSource).toContain("cross-provider");
  });

  it("defaults to per-scan when the URL has no tab param", () => {
    expect(sharedSource).toContain("PER_SCAN");
    expect(sharedSource).toMatch(
      /getCompliancePageTab\([\s\S]*\): CompliancePageTab/,
    );
  });

  it("uses URL-based state via Next router push", () => {
    expect(tabsSource).toContain("useRouter");
    expect(tabsSource).toContain("router.push");
    // Per-scan is the canonical default — leaving the tab param off keeps the
    // existing bookmarks working.
    expect(tabsSource).toContain('params.delete("tab")');
  });

  it("exposes both content slots so RSC payload composes server-side", () => {
    expect(tabsSource).toContain("perScanContent");
    expect(tabsSource).toContain("crossProviderContent");
  });
});
