"use client";

import { useEffect } from "react";

import {
  buildAccountLookup,
  buildOrgTreeData,
} from "@/actions/organizations/organizations.adapter";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { Badge } from "@/components/shadcn";
import { TreeView } from "@/components/shadcn/tree-view";
import { useOrgSetupStore } from "@/store/organizations/store";

import { OrgAccountTreeItem, TREE_ITEM_MODE } from "./org-account-tree-item";

interface OrgAccountSelectionProps {
  onBack: () => void;
  onNext: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function OrgAccountSelection({
  onBack,
  onNext,
  onFooterChange,
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

  const selectedCount = selectedAccountIds.length;

  useEffect(() => {
    onFooterChange({
      showBack: true,
      backLabel: "Back",
      onBack,
      showAction: true,
      actionLabel: "Next",
      actionDisabled: selectedCount === 0,
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: onNext,
    });
  }, [onBack, onFooterChange, onNext, selectedCount]);

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
    </div>
  );
}
