import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { UNIVERSAL_FRAMEWORKS } from "./universal-frameworks";

/**
 * Guards the hardcoded ``UNIVERSAL_FRAMEWORKS`` catalogue against drifting out
 * of sync with the SDK. The cross-provider tab iterates this catalogue to know
 * which universal frameworks to roll up, but the SDK is the source of truth:
 * every ``prowler/compliance/<framework>.json`` whose ``requirements[].checks``
 * is a per-provider dict is a universal framework.
 *
 * This test mirrors ``ComplianceFramework.get_providers()`` in
 * ``prowler/lib/check/compliance_models.py`` (it derives the compatible
 * providers from the union of ``checks`` keys) so a new universal JSON — or a
 * provider added to an existing one — fails CI until the catalogue is updated.
 *
 * ``ui/`` and ``prowler/`` are siblings in the monorepo, so resolve the SDK
 * compliance dir three levels up from ``ui/lib/compliance/``.
 */
const currentDir = path.dirname(fileURLToPath(import.meta.url));
const sdkComplianceDir = path.resolve(
  currentDir,
  "../../../prowler/compliance",
);

interface SdkUniversalFramework {
  id: string;
  providers: string[];
}

const readSdkUniversalFrameworks = (): SdkUniversalFramework[] => {
  const frameworks: SdkUniversalFramework[] = [];

  for (const file of readdirSync(sdkComplianceDir)) {
    if (!file.endsWith(".json")) continue;

    const raw = JSON.parse(
      readFileSync(path.join(sdkComplianceDir, file), "utf8"),
    );

    // Universal frameworks use the lowercase ``requirements`` key (legacy
    // per-provider JSONs live under prowler/compliance/<provider>/ and use
    // ``Requirements``). A universal requirement carries ``checks`` as a dict
    // keyed by provider.
    const requirements = raw?.requirements;
    if (!Array.isArray(requirements)) continue;

    const providers = new Set<string>();
    let hasPerProviderChecks = false;
    for (const req of requirements) {
      const checks = req?.checks;
      if (checks && typeof checks === "object" && !Array.isArray(checks)) {
        hasPerProviderChecks = true;
        for (const key of Object.keys(checks)) {
          providers.add(key.toLowerCase());
        }
      }
    }
    if (!hasPerProviderChecks) continue;

    frameworks.push({
      id: file.replace(/\.json$/, ""),
      providers: Array.from(providers).sort(),
    });
  }

  return frameworks;
};

describe("UNIVERSAL_FRAMEWORKS stays in sync with the SDK", () => {
  it("can locate the SDK compliance directory", () => {
    // A broken path would make every assertion below vacuously pass, so fail
    // loudly instead. This test requires the full monorepo checkout.
    expect(
      existsSync(sdkComplianceDir),
      `SDK compliance dir not found at ${sdkComplianceDir}. This sync test ` +
        "requires the monorepo checkout (ui/ and prowler/ as siblings).",
    ).toBe(true);
  });

  const sdkUniversals = existsSync(sdkComplianceDir)
    ? readSdkUniversalFrameworks()
    : [];

  it("discovers the known universal frameworks", () => {
    // Backstop against the detection logic silently yielding an empty list.
    expect(sdkUniversals.length).toBeGreaterThanOrEqual(3);
  });

  it.each(sdkUniversals.map((fw) => [fw.id, fw] as const))(
    "lists %s with the providers the SDK declares",
    (_id, fw) => {
      const entry = UNIVERSAL_FRAMEWORKS.find((e) => e.id === fw.id);
      expect(
        entry,
        `Universal framework "${fw.id}" exists in prowler/compliance/ but is ` +
          "missing from UNIVERSAL_FRAMEWORKS " +
          "(ui/lib/compliance/universal-frameworks.ts). Add an entry for it.",
      ).toBeDefined();
      expect(
        Array.from(entry!.providers).sort(),
        `Providers for "${fw.id}" are out of sync with the SDK checks dict.`,
      ).toEqual(fw.providers);
    },
  );

  it("does not list frameworks that no longer exist in the SDK", () => {
    const sdkIds = new Set(sdkUniversals.map((fw) => fw.id));
    for (const entry of UNIVERSAL_FRAMEWORKS) {
      expect(
        sdkIds.has(entry.id),
        `UNIVERSAL_FRAMEWORKS lists "${entry.id}" but no matching universal ` +
          "JSON exists in prowler/compliance/. Remove the stale entry.",
      ).toBe(true);
    }
  });
});
