import type {
  AttributesData,
  AttributesItemData,
  RequirementItemData,
  RequirementsData,
} from "@/types/compliance";

import type {
  AccountBreakdownEntry,
  CrossAccountAccountRef,
  CrossAccountOverviewAttributes,
  CrossAccountRequirementExtras,
} from "../_types";

/** Candidate display names a framework mapper may give this requirement.
 *
 *  Unlike the cross-provider view (whose three universal frameworks all
 *  compose `id - name`), cross-account serves EVERY framework, and mappers
 *  disagree on the composed name: CSA/CIS-Controls/DORA use `id - name`,
 *  CIS/CCC/PCI use the bare `id`, the generic mapper uses the bare `name`.
 *  The extras map registers every candidate so the join works regardless of
 *  which mapper renders the framework. */
const candidateRequirementNames = (id: string, name: string): string[] => {
  const candidates = [id];
  if (name) {
    candidates.push(name, `${id} - ${name}`);
  }
  return candidates;
};

/** Display label for an account column: alias when set, uid otherwise. */
export const accountDisplayLabel = (account: CrossAccountAccountRef): string =>
  account.alias ? `${account.alias} (${account.uid})` : account.uid;

/**
 * Convert a cross-account overview into the `{AttributesData,
 * RequirementsData}` pair the per-scan compliance mappers consume — the
 * cross-account sibling of `crossProviderToMapperInput`. The per-provider
 * template already ships each requirement's metadata as a list, so it feeds
 * `attributes.metadata` directly, and `check_ids` is the single flat list
 * every account shares.
 */
export const crossAccountToMapperInput = (
  attrs: CrossAccountOverviewAttributes,
): { attributesData: AttributesData; requirementsData: RequirementsData } => {
  const attributeItems: AttributesItemData[] = [];
  const requirementItems: RequirementItemData[] = [];

  for (const requirement of attrs.requirements) {
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
          metadata: (requirement.attributes ??
            []) as AttributesItemData["attributes"]["attributes"]["metadata"],
          check_ids: requirement.check_ids ?? [],
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
 * Cross-account context for each requirement, keyed by the exact composed
 * name the mappers produce, so renderers can join per-account statuses and
 * scan ids onto mapped requirements without touching the mappers.
 */
export const buildAccountExtrasMap = (
  attrs: CrossAccountOverviewAttributes,
): Map<string, CrossAccountRequirementExtras> => {
  const extras = new Map<string, CrossAccountRequirementExtras>();

  for (const requirement of attrs.requirements) {
    const entry: CrossAccountRequirementExtras = {
      requirementId: requirement.id,
      accounts: requirement.accounts,
      checkIds: requirement.check_ids ?? [],
      scanIdsByAccount: attrs.scan_ids_by_account,
    };
    for (const name of candidateRequirementNames(
      requirement.id,
      requirement.name,
    )) {
      // First registration wins on the (unlikely) cross-requirement
      // collision, so a bare-name key never hijacks another entry's id key.
      if (!extras.has(name)) {
        extras.set(name, entry);
      }
    }
  }

  return extras;
};

/**
 * Per-account score summary for the coverage panel. Keeps the server's
 * account order (sorted by alias). Score is the pass percentage over
 * non-manual requirements the account contributed.
 */
export const computeAccountBreakdown = (
  attrs: CrossAccountOverviewAttributes,
): AccountBreakdownEntry[] =>
  attrs.accounts.map((account) => {
    let pass = 0;
    let fail = 0;
    let manual = 0;

    for (const requirement of attrs.requirements) {
      const status = requirement.accounts[account.id];
      if (status === "PASS") pass += 1;
      else if (status === "FAIL") fail += 1;
      else if (status === "MANUAL") manual += 1;
    }

    const scored = pass + fail;
    return {
      id: account.id,
      label: accountDisplayLabel(account),
      pass,
      fail,
      manual,
      total: pass + fail + manual,
      score: scored > 0 ? Math.round((pass / scored) * 100) : 0,
    };
  });
