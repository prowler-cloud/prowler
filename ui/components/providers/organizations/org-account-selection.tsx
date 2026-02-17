"use client";

import { ChevronLeft, ChevronRight } from "lucide-react";

import {
  buildAccountLookup,
  buildOrgTreeData,
} from "@/actions/organizations/organizations.adapter";
import { Badge, Button } from "@/components/shadcn";
import { TreeView } from "@/components/shadcn/tree-view";
import { useOrgSetupStore } from "@/store/organizations/store";

import { OrgAccountTreeItem, TREE_ITEM_MODE } from "./org-account-tree-item";

interface OrgAccountSelectionProps {
  onBack: () => void;
  onNext: () => void;
}

export function OrgAccountSelection({
  onBack,
  onNext,
}: OrgAccountSelectionProps) {
  const {
    organizationName,
    organizationExternalId,
    discoveryResult,
    selectedAccountIds,
    accountAliases,
    setSelectedAccountIds,
    setAccountAlias,
  } = useOrgSetupStore();

  if (!discoveryResult) {
    return (
      <div className="text-muted-foreground py-8 text-center text-sm">
        No discovery data available.
      </div>
    );
  }

  const treeData = buildOrgTreeData(discoveryResult);
  const accountLookup = buildAccountLookup(discoveryResult);

  const totalAccounts = discoveryResult.accounts.length;
  const selectedCount = selectedAccountIds.length;

  return (
    <div className="flex flex-col gap-5">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <Badge variant="outline">AWS</Badge>
          <span className="text-sm font-medium">{organizationName}</span>
          {organizationExternalId && (
            <Badge variant="secondary">{organizationExternalId}</Badge>
          )}
        </div>
        <p className="text-muted-foreground text-sm">
          Select the accounts you want to connect. {selectedCount} of{" "}
          {totalAccounts} accounts selected.
        </p>
      </div>

      {/* Tree */}
      <div className="max-h-80 overflow-y-auto rounded-md border p-2">
        <TreeView
          data={treeData}
          showCheckboxes
          enableSelectChildren
          expandAll
          selectedIds={selectedAccountIds}
          onSelectionChange={setSelectedAccountIds}
          renderItem={(params) => (
            <OrgAccountTreeItem
              params={params}
              mode={TREE_ITEM_MODE.SELECTION}
              accountLookup={accountLookup}
              aliases={accountAliases}
              onAliasChange={setAccountAlias}
            />
          )}
        />
      </div>

      {/* Actions */}
      <div className="flex justify-end gap-3">
        <Button type="button" variant="ghost" onClick={onBack}>
          <ChevronLeft className="mr-1 size-4" />
          Back
        </Button>
        <Button type="button" onClick={onNext} disabled={selectedCount === 0}>
          Next
          <ChevronRight className="ml-1 size-4" />
        </Button>
      </div>
    </div>
  );
}
