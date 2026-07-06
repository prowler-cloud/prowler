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

  describe("Cross-Provider tab trigger structure", () => {
    // The active-tab underline sizes itself off ``:not(:first-child)`` /
    // ``:last-child`` selectors keyed on the trigger's OWN position among
    // its siblings (see components/shadcn/tabs/tabs.tsx). Wrapping the
    // trigger in an extra element breaks that and silently drops both the
    // inter-tab padding AND the underline's left inset, which previously
    // produced a visibly misaligned (then, when only half-fixed, a
    // vanished) active indicator on this tab alone. The fix: only pay that
    // wrapper tax on the OSS/disabled branch where it's structurally
    // required (tooltip-on-disabled + upsell badge) — the common, enabled
    // case renders a plain trigger exactly like every other tab in the app
    // (see app/(prowler)/providers/provider-page-tabs.tsx) and needs no
    // compensating classes at all.
    const ternaryMatch = tabsSource.match(
      /\{crossProviderEnabled \? \(([\s\S]*?)\) : \(([\s\S]*?)\)\}/,
    );

    it("finds the enabled/disabled branches", () => {
      expect(
        ternaryMatch,
        "expected to find the crossProviderEnabled ternary",
      ).not.toBe(null);
    });

    const enabledBranch = ternaryMatch?.[1] ?? "";
    const disabledBranch = ternaryMatch?.[2] ?? "";

    it("renders a plain, unwrapped trigger when the tab is enabled — same shape as every other tab", () => {
      expect(enabledBranch).toContain("<TabsTrigger");
      expect(enabledBranch).not.toContain("<span");
      // No manual padding/underline-inset compensation needed: this branch
      // is a direct child of TabsList, so the shared component's own
      // ``:not(:first-child)``/``:last-child`` rules apply automatically.
      expect(enabledBranch).not.toContain("className=");
    });

    it("keeps the compensating padding and underline inset on the disabled/OSS branch", () => {
      expect(disabledBranch).toContain("<span");
      const triggerMatch = disabledBranch.match(
        /<TabsTrigger[\s\S]*?className="([^"]*)"/,
      );
      expect(
        triggerMatch,
        "expected the disabled TabsTrigger to carry a className",
      ).not.toBe(null);
      expect(triggerMatch![1]).toContain("pl-4");
      expect(triggerMatch![1]).toContain("after:left-4");
    });
  });
});
