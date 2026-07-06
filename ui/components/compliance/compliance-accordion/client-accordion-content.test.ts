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

  describe("scope-aware cache invalidation", () => {
    // Regression coverage for a real bug: switching the provider-type /
    // provider-id / region filters on the cross-provider compliance page
    // re-renders an already-expanded requirement with a *different* scan
    // scope, but page/pageSize/sort/mutedFilter can stay identical — so a
    // guard keyed only on those would wrongly treat the new scope as
    // "already loaded" and keep showing findings from the filtered-out
    // provider/region.

    it("derives the fetch scope from scan/check identity AND region, not just pagination/sort/mute", () => {
      expect(source).toMatch(
        /const scopeSignature = isCrossProvider\s*\n\s*\?\s*JSON\.stringify\(\{\s*scanIdsByProvider,\s*checkIdsByProvider,\s*region\s*\}\)/,
      );
      // The per-scan branch's signature must also fold in ``region`` — a
      // requirement with the same scanId/check_ids but a different region
      // filter is a different fetch.
      expect(source).toMatch(
        /:\s*`\$\{scanId\}\|\$\{\(requirement\.check_ids \|\| \[\]\)\.join\(","\)\}\|\$\{region\}`/,
      );
    });

    it("includes the scope signature in the already-loaded skip guard", () => {
      const guardMatch = source.match(
        /if \(\s*\n([\s\S]*?)\n\s*\) \{\s*\n\s*return;/,
      );
      expect(guardMatch, "expected to find the skip-fetch guard").not.toBe(
        null,
      );
      const guardBody = guardMatch![1];
      expect(guardBody).toContain("loadedScopeRef.current === scopeSignature");
      // The pre-existing guard members must still be present — this test
      // should fail if a refactor drops one of them, not just if scope is
      // missing.
      expect(guardBody).toContain("loadedPageRef.current === pageNumber");
      expect(guardBody).toContain("loadedMutedRef.current === mutedFilter");
    });

    it("only marks the scope as loaded once the fetch actually commits, for both branches", () => {
      // Marking it eagerly (before the fetch resolves) would let a
      // superseded in-flight request's cleanup permanently strand the
      // component at ``findings === null`` — see the neighboring comment
      // in source for the full race explanation.
      const commitPattern = /loadedScopeRef\.current = scopeSignature;/g;
      const commitIndices = Array.from(source.matchAll(commitPattern)).map(
        (match) => match.index!,
      );
      expect(commitIndices).toHaveLength(2); // cross-provider branch + per-scan branch

      for (const index of commitIndices) {
        // A cancellation check must precede the commit nearby, and nothing
        // awaits in between — i.e. the ref is only written synchronously
        // after the fetch has already resolved and the in-flight request
        // wasn't superseded by a newer one.
        const window = source.slice(Math.max(0, index - 250), index);
        const guardIndex = window.search(/if \(cancelled\) return;/);
        expect(
          guardIndex,
          "expected a nearby cancellation check",
        ).toBeGreaterThanOrEqual(0);
        expect(window.slice(guardIndex)).not.toContain("await ");
      }
    });

    it("re-runs the effect when the scope signature changes", () => {
      // scopeSignature is derived from requirement/scanIdsByProvider/
      // checkIdsByProvider/region, which are already effect dependencies,
      // so this mostly guards against someone deleting the dependency
      // outright under the (wrong) assumption it's redundant.
      const depsMatch = source.match(/\}, \[([\s\S]*?)\]\);/);
      expect(
        depsMatch,
        "expected to find the effect's dependency array",
      ).not.toBe(null);
      expect(depsMatch![1]).toContain("scopeSignature");
    });
  });
});
