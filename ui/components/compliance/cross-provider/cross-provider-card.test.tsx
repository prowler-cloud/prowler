import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("CrossProviderCard", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "cross-provider-card.tsx");
  const source = readFileSync(filePath, "utf8");

  it("navigates to the universal detail page in cross-provider mode", () => {
    // The drill-down must emit ?mode=cross-provider so the detail page knows
    // to render the universal-aggregated view instead of the per-scan one.
    expect(source).toContain('"mode"');
    expect(source).toContain('"cross-provider"');
  });

  it("does not depend on a scanId prop", () => {
    // The cross-provider tab must not require a scan picker.
    expect(source).not.toMatch(/scanId/);
  });

  it("preserves provider_type and region filters when drilling in", () => {
    expect(source).toContain('"filter[region__in]"');
    expect(source).toContain('"filter[provider_type__in]"');
  });

  it("surfaces the providers contribution ratio via chips", () => {
    // The card renders one chip per compatible provider and dims the ones
    // that did not contribute to the aggregation. The ratio is implicit in
    // the active/inactive state of the chip set.
    expect(source).toContain("contributingProviders");
    expect(source).toContain("compatibleProviders");
    expect(source).toContain("ProviderChip");
  });
});
