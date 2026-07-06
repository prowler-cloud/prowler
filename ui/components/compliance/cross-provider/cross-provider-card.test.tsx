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

  it("renders each provider as a compact icon, not a full uppercase-label pill", () => {
    // Regression guard: frameworks can declare 15+ compatible providers (CIS
    // Controls 8.1 has 18) — one full-width uppercase-label pill per
    // provider used to wrap across 4-5 rows, dwarfing every other card in
    // the same grid. The fix reuses the same compact icon-square language
    // as the per-domain provider heatmap on the detail page
    // (CrossProviderDomainTitle) instead of spelling out each provider name.
    expect(source).toContain("ProviderBadgeIcon");
    // ``{providerKey}`` as JSX *text content* (old pill label) vs. as a prop
    // value (``providerKey={providerKey}``, still expected) — only the
    // former is the regression this guards against.
    expect(source).not.toMatch(/>\s*\{providerKey\}\s*</);
  });

  it("links the info button next to the title to the framework's Prowler Hub page", () => {
    expect(source).toContain("getProwlerHubComplianceUrl(complianceId)");
    expect(source).toContain('target="_blank"');
  });

  it("stops the info button's click from also triggering the card's own drill-down navigation", () => {
    // Regression guard: the whole card is a click target (onClick={navigateToDetail}).
    // Without stopPropagation, opening the Hub link would also navigate the
    // card to the detail page underneath the new tab.
    expect(source).toContain("e.stopPropagation()");
  });
});
