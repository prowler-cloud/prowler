import type {
  AttributesData,
  AttributesItemData,
  CheckProviderTypesMap,
  RequirementItemData,
  RequirementsData,
} from "@/types/compliance";
import { isKnownProviderType, PROVIDER_TYPES } from "@/types/providers";

import {
  CROSS_PROVIDER_OVERVIEW_RESULT_STATUS,
  type CrossProviderFrameworkSummary,
  type CrossProviderOverviewAttributes,
  type CrossProviderOverviewResult,
  type CrossProviderRequirementExtras,
  type ProviderBreakdownEntry,
  type ProviderCheckIdsMap,
} from "../_types";

import type { CrossProviderFrameworkEntry } from "./cross-provider-frameworks";
import { candidateRequirementNames } from "./requirement-names";

/**
 * Convert a cross-provider overview into the `{AttributesData,
 * RequirementsData}` pair the per-scan compliance mappers consume, so the
 * existing framework mappers (grouping, counters, detail fields) render the
 * requirements accordion without a parallel cross-provider pipeline.
 *
 * The mappers read `attributes.attributes.metadata[0]` for framework-specific
 * fields (Section, Pillar, …), so each requirement's flat `attributes` dict is
 * wrapped in a single-element array. `check_ids` is the deduped union across
 * providers — per-provider splits travel separately via
 * {@link buildRequirementExtrasMap}.
 */
export const crossProviderToMapperInput = (
  attrs: CrossProviderOverviewAttributes,
): { attributesData: AttributesData; requirementsData: RequirementsData } => {
  const attributeItems: AttributesItemData[] = [];
  const requirementItems: RequirementItemData[] = [];

  for (const requirement of attrs.requirements) {
    const allCheckIds = Array.from(
      new Set(
        Object.values(requirement.check_ids_by_provider ?? {}).flatMap(
          (ids) => ids ?? [],
        ),
      ),
    );

    attributeItems.push({
      type: "compliance-requirements-attributes",
      id: requirement.id,
      attributes: {
        framework_description: attrs.description || "",
        name: requirement.name,
        framework: attrs.framework,
        version: attrs.version || "",
        description: requirement.description || "",
        attributes: {
          metadata: [
            requirement.attributes,
          ] as AttributesItemData["attributes"]["attributes"]["metadata"],
          check_ids: allCheckIds,
        },
      },
    });

    requirementItems.push({
      type: "compliance-requirements-details",
      id: requirement.id,
      attributes: {
        framework: attrs.framework,
        version: attrs.version || "",
        description: requirement.description || "",
        status: requirement.status,
      },
    });
  }

  return {
    attributesData: { data: attributeItems },
    requirementsData: { data: requirementItems },
  };
};

/**
 * Cross-provider context for each requirement, keyed by every name a mapper
 * may give it, so renderers can join per-provider statuses and
 * scan/check splits onto mapped requirements without touching the mappers.
 */
export const buildRequirementExtrasMap = (
  attrs: CrossProviderOverviewAttributes,
): Map<string, CrossProviderRequirementExtras> => {
  const extras = new Map<string, CrossProviderRequirementExtras>();

  for (const requirement of attrs.requirements) {
    const entry: CrossProviderRequirementExtras = {
      requirementId: requirement.id,
      providers: requirement.providers,
      checkIdsByProvider: requirement.check_ids_by_provider ?? {},
      scanIdsByProvider: attrs.scan_ids_by_provider,
    };
    for (const name of candidateRequirementNames(
      requirement.id,
      requirement.name,
    )) {
      // First registration wins, so a bare-name key never hijacks an id key.
      if (!extras.has(name)) {
        extras.set(name, entry);
      }
    }
  }

  return extras;
};

/**
 * Invert a requirement's per-provider check split into check id → provider
 * types, so the combined checks list can label each check. Iterates
 * PROVIDER_TYPES for a stable icon order regardless of API key order.
 */
export const invertCheckIdsByProvider = (
  checkIdsByProvider: ProviderCheckIdsMap,
): CheckProviderTypesMap => {
  const byCheck: CheckProviderTypesMap = {};

  for (const provider of PROVIDER_TYPES) {
    for (const checkId of checkIdsByProvider[provider] ?? []) {
      (byCheck[checkId] ??= []).push(provider);
    }
  }

  return byCheck;
};

/**
 * Per-provider score summary for the coverage panel and framework cards.
 * Scanned providers come first, each group sorted alphabetically; entries the
 * UI cannot render (unknown provider types) are dropped. Score is the pass
 * percentage over non-manual requirements the provider contributed.
 */
export const computeProviderBreakdown = (
  attrs: CrossProviderOverviewAttributes,
): ProviderBreakdownEntry[] => {
  const contributing = new Set(attrs.providers);

  return attrs.compatible_providers
    .filter(isKnownProviderType)
    .sort((a, b) => {
      const aScanned = contributing.has(a);
      if (aScanned !== contributing.has(b)) return aScanned ? -1 : 1;
      return a.localeCompare(b);
    })
    .map((provider) => {
      let pass = 0;
      let fail = 0;
      let manual = 0;

      for (const requirement of attrs.requirements) {
        const status = requirement.providers[provider];
        if (status === "PASS") pass += 1;
        else if (status === "FAIL") fail += 1;
        else if (status === "MANUAL") manual += 1;
      }

      const scored = pass + fail;
      return {
        provider,
        pass,
        fail,
        manual,
        total: pass + fail + manual,
        score: scored > 0 ? Math.round((pass / scored) * 100) : 0,
        unscanned: !contributing.has(provider),
      };
    });
};

/** The card roll-up of one universal framework; zeroed with every provider
 *  unscanned when the overview has no data for it. */
export const toCrossProviderSummary = (
  entry: CrossProviderFrameworkEntry,
  result: CrossProviderOverviewResult,
): CrossProviderFrameworkSummary => {
  const attrs =
    result.status === CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS
      ? result.response.data?.attributes
      : undefined;
  const base = {
    complianceId: entry.complianceId,
    title: entry.title,
    version: entry.version,
    description: entry.description,
  };

  if (!attrs) {
    return {
      ...base,
      requirementsPassed: 0,
      requirementsFailed: 0,
      requirementsManual: 0,
      totalRequirements: 0,
      // Chips need an icon and a label, which only known types have.
      providerBreakdown: entry.providerTypes
        .filter(isKnownProviderType)
        .map((provider) => ({
          provider,
          pass: 0,
          fail: 0,
          manual: 0,
          total: 0,
          score: 0,
          unscanned: true,
        })),
    };
  }

  return {
    ...base,
    requirementsPassed: attrs.requirements_passed,
    requirementsFailed: attrs.requirements_failed,
    requirementsManual: attrs.requirements_manual,
    totalRequirements: attrs.total_requirements,
    providerBreakdown: computeProviderBreakdown(attrs),
  };
};
