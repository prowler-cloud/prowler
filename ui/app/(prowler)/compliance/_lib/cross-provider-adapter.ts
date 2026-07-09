import type {
  AttributesData,
  AttributesItemData,
  RequirementItemData,
  RequirementsData,
} from "@/types/compliance";
import { PROVIDER_TYPES, type ProviderType } from "@/types/providers";

import type {
  CrossProviderOverviewAttributes,
  CrossProviderRequirementExtras,
  ProviderBreakdownEntry,
} from "../_types";

/** The composed display name the per-scan mappers give every requirement.
 *  Shared with `buildRequirementExtrasMap` so the extras join never parses
 *  strings back apart. */
const composeRequirementName = (id: string, name: string): string =>
  name ? `${id} - ${name}` : id;

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
      new Set(Object.values(requirement.check_ids_by_provider ?? {}).flat()),
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
 * Cross-provider context for each requirement, keyed by the exact composed
 * name the mappers produce, so renderers can join per-provider statuses and
 * scan/check splits onto mapped requirements without touching the mappers.
 */
export const buildRequirementExtrasMap = (
  attrs: CrossProviderOverviewAttributes,
): Map<string, CrossProviderRequirementExtras> => {
  const extras = new Map<string, CrossProviderRequirementExtras>();

  for (const requirement of attrs.requirements) {
    extras.set(composeRequirementName(requirement.id, requirement.name), {
      requirementId: requirement.id,
      providers: requirement.providers,
      checkIdsByProvider: requirement.check_ids_by_provider ?? {},
      scanIdsByProvider: attrs.scan_ids_by_provider,
    });
  }

  return extras;
};

const isKnownProviderType = (value: string): value is ProviderType =>
  (PROVIDER_TYPES as readonly string[]).includes(value);

/**
 * Per-provider score summary for the coverage panel and framework cards.
 * Providers are listed in `compatible_providers` order; entries the UI cannot
 * render (unknown provider types) are dropped. Score is the pass percentage
 * over non-manual requirements the provider contributed.
 */
export const computeProviderBreakdown = (
  attrs: CrossProviderOverviewAttributes,
): ProviderBreakdownEntry[] => {
  const contributing = new Set(attrs.providers);

  return attrs.compatible_providers
    .filter(isKnownProviderType)
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
