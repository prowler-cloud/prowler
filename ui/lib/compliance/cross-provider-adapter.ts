import type {
  AttributesData,
  AttributesItemData,
  CrossProviderComplianceOverviewAttributes,
  RequirementItemData,
  RequirementsData,
} from "@/types/compliance";

/**
 * Convert a cross-provider compliance overview into the shape the per-scan
 * compliance mappers expect.
 *
 * The per-scan flow consumes two parallel JSON:API responses:
 *   - ``AttributesData`` — per-requirement metadata (Section/CCMLite/...)
 *     plus the list of check IDs the requirement runs.
 *   - ``RequirementsData`` — per-requirement status for the selected scan.
 *
 * The cross-provider endpoint already exposes everything in a single
 * resource where each requirement carries:
 *   - flat ``attributes`` (one element of the universal JSON metadata array
 *     wrapped in a list — the mappers read ``metadata[0]`` so this works).
 *   - rolled-up ``status`` derived server-side.
 *   - ``providers`` map (per-provider statuses that fed the roll-up).
 *   - ``check_ids_by_provider`` map (universal-framework-declared check
 *     IDs per contributing provider).
 *
 * This adapter rebuilds the two-payload pair so the existing CSA-CCM (and
 * any future framework) mapper renders a hierarchical accordion without
 * needing a parallel cross-provider pipeline.
 *
 * The returned ``AttributesItemData`` carries the cross-provider context
 * (``providers``, ``check_ids_by_provider``, ``scan_ids_by_provider``) on
 * its inner ``attributes.attributes`` slot. Mappers then copy those
 * augmentations onto the ``Requirement`` literal so the renderers can
 * decide whether to expose per-provider chips, breakdown tables, and
 * per-scan finding queries.
 */
export const crossProviderToMapperInput = (
  attrs: CrossProviderComplianceOverviewAttributes,
): { attributesData: AttributesData; requirementsData: RequirementsData } => {
  const scanIdsByProvider = attrs.scan_ids_by_provider || {};

  const attributeItems: AttributesItemData[] = [];
  const requirementItems: RequirementItemData[] = [];

  for (const req of attrs.requirements) {
    const checkIdsByProvider = req.check_ids_by_provider || {};
    const allCheckIds = Array.from(
      new Set(
        Object.values(checkIdsByProvider).flatMap((ids) =>
          Array.isArray(ids) ? ids : [],
        ),
      ),
    );

    attributeItems.push({
      type: "compliance-requirements-attributes",
      id: req.id,
      attributes: {
        framework_description: attrs.description || "",
        name: req.name,
        framework: attrs.framework,
        version: attrs.version || "",
        description: req.description || "",
        attributes: {
          // The mappers (e.g. CSA) read ``metadata[0]`` and pull
          // framework-specific fields off it. Wrap the flat dict in a
          // single-element list to satisfy that contract.
          metadata: [
            req.attributes as unknown as AttributesItemData["attributes"]["attributes"]["metadata"][number],
          ] as AttributesItemData["attributes"]["attributes"]["metadata"],
          check_ids: allCheckIds,
          providers: req.providers,
          check_ids_by_provider: checkIdsByProvider,
          scan_ids_by_provider: scanIdsByProvider,
        },
      },
    });

    requirementItems.push({
      type: "compliance-requirements-details",
      id: req.id,
      attributes: {
        framework: attrs.framework,
        version: attrs.version || "",
        description: req.description || "",
        status: req.status,
      },
    });
  }

  return {
    attributesData: { data: attributeItems },
    requirementsData: { data: requirementItems },
  };
};
