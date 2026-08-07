import { Box, Folder } from "lucide-react";

import {
  APPLY_STATUS,
  ApplyDiscoveryPayload,
  AwsDiscoveryResult,
  AwsOrgHierarchy,
  AzureDiscoveryResult,
  AzureOrgHierarchy,
  GcpDiscoveryResult,
  GcpOrgHierarchy,
  NODE_KIND,
  OrgCandidate,
  OrgHierarchy,
  ORGANIZATION_TYPE,
} from "@/types/organizations";
import { TreeDataItem } from "@/types/tree";

/**
 * Ingestion mapper: AWS discovery wire result → normalized hierarchy model.
 *
 * Roots are collapsed away — OUs and accounts that sit directly under a root
 * carry the root id as their `parentId`, which is absent from the node set, so
 * tree rebuild treats them as top-level. Provider-specific dispatch happens here
 * once, so downstream machinery is kind-driven and provider-agnostic.
 */
export function mapAwsDiscovery(result: AwsDiscoveryResult): AwsOrgHierarchy {
  const root = result.roots[0];
  if (!root) throw new Error("Invalid root organization");

  return {
    orgType: ORGANIZATION_TYPE.AWS,
    organization: {
      uid: root.id,
      name: root.name,
    },
    nodes: result.organizational_units.map((ou) => ({
      id: ou.id,
      kind: NODE_KIND.ORGANIZATIONAL_UNIT,
      name: ou.name,
      parentId: ou.parent_id,
    })),
    candidates: result.accounts.map((account) => ({
      uid: account.id,
      label: account.name,
      parentId: account.parent_id,
      registration: account.registration,
    })),
  };
}

/** Bare id of a canonical resource name (`folders/123` → `123`). */
function resourceId(name: string): string {
  return name.split("/").at(-1) ?? name;
}

/**
 * Ingestion mapper: GCP discovery wire result → normalized hierarchy model.
 *
 * A folder's identity is its resource `name` (`folders/{id}`), which is exactly
 * what its children carry as `parent`, so nesting matches on that ref. Parents
 * pointing at the organization are absent from the node set, so tree rebuild
 * treats those folders/projects as top-level.
 */
export function mapGcpDiscovery(result: GcpDiscoveryResult): GcpOrgHierarchy {
  return {
    orgType: ORGANIZATION_TYPE.GCP,
    organization: {
      // Bare id: what the user typed and what the organization stores as
      // `external_id`.
      uid: resourceId(result.organization.name),
      name: result.organization.display_name,
    },
    nodes: result.folders.map((folder) => ({
      id: folder.name,
      kind: NODE_KIND.FOLDER,
      name: folder.display_name || folder.name,
      parentId: folder.parent,
    })),
    candidates: result.projects.map((project) => ({
      uid: project.project_id,
      label: project.display_name || project.project_id,
      parentId: project.parent,
      registration: project.registration,
    })),
  };
}

/**
 * Ingestion mapper: Azure discovery wire result → normalized hierarchy model.
 *
 * A management group's identity is its canonical resource ID
 * (`/providers/Microsoft.Management/managementGroups/{name}`), which is exactly
 * what its children carry as `parent_id`, so nesting matches on that ref. The
 * selected root group is collapsed away — it is absent from the node set, so
 * groups and subscriptions parented by it rebuild as top-level.
 */
export function mapAzureDiscovery(
  result: AzureDiscoveryResult,
): AzureOrgHierarchy {
  return {
    orgType: ORGANIZATION_TYPE.AZURE,
    organization: {
      // Tenant id: what the user typed and what the organization stores as
      // `external_id`.
      uid: result.root.tenant_id,
      name: result.root.display_name || result.root.name,
    },
    nodes: result.management_groups.map((group) => ({
      id: group.id,
      kind: NODE_KIND.MANAGEMENT_GROUP,
      name: group.display_name || group.name,
      parentId: group.parent_id,
    })),
    candidates: result.subscriptions.map((subscription) => ({
      uid: subscription.subscription_id,
      label: subscription.display_name || subscription.subscription_id,
      parentId: subscription.parent_id,
      registration: subscription.registration,
    })),
  };
}

/**
 * Transforms the normalized hierarchy into hierarchical TreeDataItem[] for
 * TreeView. Container nodes (OUs / folders) nest candidates (accounts /
 * projects); an item is top-level when its `parentId` is not a known node
 * (i.e. it hangs directly off the organization root). Kind-driven — no ID
 * prefixes. Blocked candidates are marked disabled.
 */
export function buildOrgTreeData(hierarchy: OrgHierarchy): TreeDataItem[] {
  const itemMap = new Map<string, TreeDataItem>();
  const parentById = new Map<string, string>();
  const nodeIds = new Set(hierarchy.nodes.map((node) => node.id));

  for (const node of hierarchy.nodes) {
    itemMap.set(node.id, {
      id: node.id,
      name: node.name,
      icon: Folder,
      kind: node.kind,
      children: [],
    });
    parentById.set(node.id, node.parentId);
  }

  for (const candidate of hierarchy.candidates) {
    const isBlocked =
      candidate.registration?.apply_status === APPLY_STATUS.BLOCKED;
    itemMap.set(candidate.uid, {
      id: candidate.uid,
      name: `${candidate.uid} — ${candidate.label}`,
      icon: Box,
      disabled: isBlocked,
    });
    parentById.set(candidate.uid, candidate.parentId);
  }

  const topLevel: TreeDataItem[] = [];

  const link = (id: string, parentId: string) => {
    const item = itemMap.get(id);
    if (!item) {
      return;
    }
    if (!nodeIds.has(parentId)) {
      topLevel.push(item);
      return;
    }
    const parent = itemMap.get(parentId);
    if (parent) {
      (parent.children ??= []).push(item);
    }
  };

  // Iterating the identity map, not the source arrays, so a duplicate wire id
  // collapses into one row instead of rendering N times. Insertion order keeps
  // containers above their sibling leaves.
  for (const id of Array.from(itemMap.keys())) {
    link(id, parentById.get(id) ?? "");
  }

  for (const item of topLevel) {
    markInertContainers(item, nodeIds);
  }

  return topLevel;
}

/**
 * Marks containers with nothing selectable underneath as disabled, bottom-up.
 * Discovery lists every folder, including project-less ones, and clicking such a
 * row would otherwise do nothing at all. Returns whether the subtree holds a
 * selectable candidate.
 */
function markInertContainers(
  item: TreeDataItem,
  nodeIds: Set<string>,
): boolean {
  if (!nodeIds.has(item.id)) {
    return !item.disabled;
  }

  // No short-circuit: every nested container has to be visited to be marked.
  let hasSelectable = false;
  for (const child of item.children ?? []) {
    hasSelectable = markInertContainers(child, nodeIds) || hasSelectable;
  }
  item.disabled = !hasSelectable;

  return hasSelectable;
}

/**
 * Returns uids of candidates that can be selected. A candidate is selectable
 * when its registration is absent or its apply_status is READY.
 */
export function getSelectableCandidateIds(hierarchy: OrgHierarchy): string[] {
  return hierarchy.candidates
    .filter((candidate) => {
      const applyStatus = candidate.registration?.apply_status;
      if (!applyStatus) {
        return true;
      }
      return applyStatus === APPLY_STATUS.READY;
    })
    .map((candidate) => candidate.uid);
}

/**
 * Creates a lookup map from candidate uid to the candidate.
 */
export function buildCandidateLookup(
  hierarchy: OrgHierarchy,
): Map<string, OrgCandidate> {
  const map = new Map<string, OrgCandidate>();
  for (const candidate of hierarchy.candidates) {
    map.set(candidate.uid, candidate);
  }
  return map;
}

/**
 * Returns the selectable candidate uids that fall under a deployment target
 * (an OU or root id), optionally including the deployment candidate itself.
 *
 * AWS-only by type (StackSet default-selection). The StackSet only rolls the role
 * out to member accounts beneath the chosen target, and the deployment account
 * gets the role via DeployLocalRole even though it usually lives outside that
 * target. Pre-selecting exactly those keeps the confirmation step in sync with
 * what was deployed.
 *
 * Falls back to every selectable candidate when the target is empty or is not a
 * known node (e.g. a root id), preserving the whole-organization default.
 */
export function getSelectableCandidateIdsForTarget(
  hierarchy: AwsOrgHierarchy,
  targetId: string,
  deploymentCandidateId?: string,
): string[] {
  const selectableCandidateIds = getSelectableCandidateIds(hierarchy);
  const normalizedTarget = targetId.trim();

  if (!normalizedTarget) {
    return selectableCandidateIds;
  }

  const isKnownNode = hierarchy.nodes.some(
    (node) => node.id === normalizedTarget,
  );

  // Only a specific node narrows the selection. A root id (whole org) or an
  // unknown target keeps the whole-organization default.
  if (!isKnownNode) {
    return selectableCandidateIds;
  }

  // Collect the target node plus all of its nested descendant nodes.
  const scopeIds = new Set<string>([normalizedTarget]);
  let addedNewNode = true;
  while (addedNewNode) {
    addedNewNode = false;
    for (const node of hierarchy.nodes) {
      if (!scopeIds.has(node.id) && scopeIds.has(node.parentId)) {
        scopeIds.add(node.id);
        addedNewNode = true;
      }
    }
  }

  const selectableSet = new Set(selectableCandidateIds);
  const scopedIds = new Set<string>();

  for (const candidate of hierarchy.candidates) {
    if (scopeIds.has(candidate.parentId) && selectableSet.has(candidate.uid)) {
      scopedIds.add(candidate.uid);
    }
  }

  if (deploymentCandidateId && selectableSet.has(deploymentCandidateId)) {
    scopedIds.add(deploymentCandidateId);
  }

  return selectableCandidateIds.filter((id) => scopedIds.has(id));
}

/**
 * Given selected candidate uids, returns node ids that are ancestors of the
 * selected candidates. AWS-only by type (client-side OU derivation for apply);
 * GCP derives folder ancestors server-side.
 */
export function getNodeIdsForSelectedCandidates(
  hierarchy: AwsOrgHierarchy,
  selectedCandidateIds: string[],
): string[] {
  const selectedSet = new Set(selectedCandidateIds);
  const nodeIds = new Set<string>();
  const allNodeIds = new Set(hierarchy.nodes.map((node) => node.id));
  const nodeParentMap = new Map<string, string>();

  for (const node of hierarchy.nodes) {
    nodeParentMap.set(node.id, node.parentId);
  }

  for (const candidate of hierarchy.candidates) {
    if (!selectedSet.has(candidate.uid)) {
      continue;
    }

    // Stops on an already-seen ancestor too: parent ids are wire data, and a
    // cycle would spin forever since re-adding to a Set never terminates.
    let currentParentId = candidate.parentId;
    const visitedParentIds = new Set<string>();
    while (
      currentParentId &&
      allNodeIds.has(currentParentId) &&
      !visitedParentIds.has(currentParentId)
    ) {
      visitedParentIds.add(currentParentId);
      nodeIds.add(currentParentId);
      currentParentId = nodeParentMap.get(currentParentId) ?? "";
    }
  }

  return Array.from(nodeIds);
}

/**
 * Builds the apply payload from the hierarchy that is being applied — the
 * hierarchy's own `orgType` is the discriminant, so there is no second source of
 * truth to drift from. The switch has no default: a new `OrgHierarchy` arm is a
 * compile error here, and the AWS-only node derivation is unreachable from any
 * other arm.
 */
export function buildApplyPayload(
  hierarchy: OrgHierarchy,
  selectedCandidateIds: string[],
  candidateAliases: Record<string, string>,
): ApplyDiscoveryPayload {
  const aliasOf = (candidateId: string) =>
    candidateAliases[candidateId]
      ? { alias: candidateAliases[candidateId] }
      : {};

  switch (hierarchy.orgType) {
    case ORGANIZATION_TYPE.AWS:
      return {
        orgType: ORGANIZATION_TYPE.AWS,
        accounts: selectedCandidateIds.map((id) => ({
          id,
          ...aliasOf(id),
        })),
        organizationalUnits: getNodeIdsForSelectedCandidates(
          hierarchy,
          selectedCandidateIds,
        ).map((id) => ({ id })),
      };
    case ORGANIZATION_TYPE.AZURE:
      return {
        orgType: ORGANIZATION_TYPE.AZURE,
        subscriptions: selectedCandidateIds.map((id) => ({
          subscription_id: id,
          ...aliasOf(id),
        })),
      };
    case ORGANIZATION_TYPE.GCP:
      return {
        orgType: ORGANIZATION_TYPE.GCP,
        projects: selectedCandidateIds.map((id) => ({
          project_id: id,
          ...aliasOf(id),
        })),
      };
  }
}
