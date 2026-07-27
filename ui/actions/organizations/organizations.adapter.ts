import { Box, Folder } from "lucide-react";

import {
  APPLY_STATUS,
  AwsDiscoveryResult,
  AwsOrgHierarchy,
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

/**
 * Transforms the normalized hierarchy into hierarchical TreeDataItem[] for
 * TreeView. Container nodes (OUs / folders) nest candidates (accounts /
 * projects); an item is top-level when its `parentId` is not a known node
 * (i.e. it hangs directly off the organization root). Kind-driven — no ID
 * prefixes. Blocked candidates are marked disabled.
 */
export function buildOrgTreeData(hierarchy: OrgHierarchy): TreeDataItem[] {
  const itemMap = new Map<string, TreeDataItem>();
  const nodeIds = new Set(hierarchy.nodes.map((node) => node.id));

  for (const node of hierarchy.nodes) {
    itemMap.set(node.id, {
      id: node.id,
      name: node.name,
      icon: Folder,
      kind: node.kind,
      children: [],
    });
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

  // Nodes before candidates so containers render above their sibling leaves.
  for (const node of hierarchy.nodes) {
    link(node.id, node.parentId);
  }
  for (const candidate of hierarchy.candidates) {
    link(candidate.uid, candidate.parentId);
  }

  return topLevel;
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
 * AWS-specific (StackSet default-selection). The StackSet only rolls the role
 * out to member accounts beneath the chosen target, and the deployment account
 * gets the role via DeployLocalRole even though it usually lives outside that
 * target. Pre-selecting exactly those keeps the confirmation step in sync with
 * what was deployed.
 *
 * Falls back to every selectable candidate when the target is empty or is not a
 * known node (e.g. a root id), preserving the whole-organization default.
 */
export function getSelectableCandidateIdsForTarget(
  hierarchy: OrgHierarchy,
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
 * selected candidates. AWS-specific (client-side OU derivation for apply); GCP
 * derives folder ancestors server-side.
 */
export function getNodeIdsForSelectedCandidates(
  hierarchy: OrgHierarchy,
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

    let currentParentId = candidate.parentId;
    while (currentParentId && allNodeIds.has(currentParentId)) {
      nodeIds.add(currentParentId);
      currentParentId = nodeParentMap.get(currentParentId) ?? "";
    }
  }

  return Array.from(nodeIds);
}
