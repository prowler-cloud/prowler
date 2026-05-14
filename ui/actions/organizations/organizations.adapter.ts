import { Box, Folder, FolderTree } from "lucide-react";

import {
  APPLY_STATUS,
  DiscoveredAccount,
  DiscoveryResult,
} from "@/types/organizations";
import { TreeDataItem } from "@/types/tree";

/**
 * Transforms flat API discovery arrays into hierarchical TreeDataItem[] for TreeView.
 *
 * Structure: OUs -> nested OUs/Accounts (leaf nodes)
 * Root nodes are used only internally for parent linking and are not rendered.
 * Accounts with apply_status === "blocked" are marked disabled.
 */
export function buildOrgTreeData(result: DiscoveryResult): TreeDataItem[] {
  const nodeMap = new Map<string, TreeDataItem>();

  for (const root of result.roots) {
    nodeMap.set(root.id, {
      id: root.id,
      name: root.name,
      icon: FolderTree,
      children: [],
    });
  }

  for (const ou of result.organizational_units) {
    nodeMap.set(ou.id, {
      id: ou.id,
      name: ou.name,
      icon: Folder,
      children: [],
    });
  }

  for (const account of result.accounts) {
    const isBlocked =
      account.registration?.apply_status === APPLY_STATUS.BLOCKED;

    nodeMap.set(account.id, {
      id: account.id,
      name: `${account.id} — ${account.name}`,
      icon: Box,
      disabled: isBlocked,
    });
  }

  for (const ou of result.organizational_units) {
    const parent = nodeMap.get(ou.parent_id);
    if (parent?.children) {
      const ouNode = nodeMap.get(ou.id);
      if (ouNode) {
        parent.children.push(ouNode);
      }
    }
  }

  for (const account of result.accounts) {
    const parent = nodeMap.get(account.parent_id);
    if (!parent) {
      continue;
    }

    if (!parent.children) {
      parent.children = [];
    }

    const accountNode = nodeMap.get(account.id);
    if (accountNode) {
      parent.children.push(accountNode);
    }
  }

  return result.roots.flatMap((root) => {
    const rootNode = nodeMap.get(root.id);
    return rootNode?.children ?? [];
  });
}

/**
 * Returns IDs of accounts that can be selected.
 * Accounts are selectable when registration is READY or not yet present.
 * Accounts with explicit non-ready states are excluded.
 */
export function getSelectableAccountIds(result: DiscoveryResult): string[] {
  return result.accounts
    .filter((account) => {
      const applyStatus = account.registration?.apply_status;
      if (!applyStatus) {
        return true;
      }
      return applyStatus === APPLY_STATUS.READY;
    })
    .map((account) => account.id);
}

/**
 * Creates a lookup map from account ID to DiscoveredAccount.
 */
export function buildAccountLookup(
  result: DiscoveryResult,
): Map<string, DiscoveredAccount> {
  const map = new Map<string, DiscoveredAccount>();
  for (const account of result.accounts) {
    map.set(account.id, account);
  }
  return map;
}

/**
 * Given selected account IDs, returns OU IDs that are ancestors of selected accounts.
 */
export function getOuIdsForSelectedAccounts(
  result: DiscoveryResult,
  selectedAccountIds: string[],
): string[] {
  const selectedSet = new Set(selectedAccountIds);
  const ouIds = new Set<string>();
  const allOuIds = new Set(result.organizational_units.map((ou) => ou.id));
  const ouParentMap = new Map<string, string>();

  for (const ou of result.organizational_units) {
    ouParentMap.set(ou.id, ou.parent_id);
  }

  for (const account of result.accounts) {
    if (!selectedSet.has(account.id)) {
      continue;
    }

    let currentParentId = account.parent_id;
    while (currentParentId && allOuIds.has(currentParentId)) {
      ouIds.add(currentParentId);
      currentParentId = ouParentMap.get(currentParentId) ?? "";
    }
  }

  return Array.from(ouIds);
}
