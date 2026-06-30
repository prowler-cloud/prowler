import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("client accordion content", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const filePath = path.join(currentDir, "client-accordion-content.tsx");
  const source = readFileSync(filePath, "utf8");

  it("uses the shared standalone finding columns instead of the legacy findings columns", () => {
    expect(source).toContain("getStandaloneFindingColumns");
    expect(source).not.toContain("getColumnFindings");
  });

  it("activates a cross-provider branch when scan_ids_by_provider is present", () => {
    // The cross-provider mode is detected by the presence of the
    // ``scan_ids_by_provider`` augmentation on the requirement. Guarding
    // this contract in source keeps regressions visible without spinning a
    // full DOM render. The reads happen through a single ``xprov`` cast
    // (see ``CrossProviderRequirement``) so we look for both spellings.
    expect(source).toMatch(/scan_ids_by_provider/);
    expect(source).toMatch(/check_ids_by_provider/);
    expect(source).toContain("CrossProviderRequirement");
  });

  it("fetches findings per contributing scan in parallel when in cross-provider mode", () => {
    expect(source).toContain("Promise.all");
    // Each parallel request scopes to a single scan and the
    // requirement's per-provider check IDs.
    expect(source).toMatch(/filter\[scan\]/);
    expect(source).toMatch(/filter\[check_id__in\]/);
  });

  it("renders a per-provider breakdown table when providers are exposed", () => {
    expect(source).toContain("Per-Provider Breakdown");
  });
});
