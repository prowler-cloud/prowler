"use client";

import { AlertTriangle } from "lucide-react";

import { AWSProviderBadge } from "@/components/icons/providers-badge";
import { WizardFooterConfig } from "@/components/providers/wizard/steps/footer-controls";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { TreeView } from "@/components/shadcn/tree-view";

import { useOrgAccountSelectionFlow } from "./hooks/use-org-account-selection-flow";
import { OrgAccountTreeItem, TREE_ITEM_MODE } from "./org-account-tree-item";

interface OrgAccountSelectionProps {
  onBack: () => void;
  onNext: () => void;
  onSkip: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function OrgAccountSelection({
  onBack,
  onNext,
  onSkip,
  onFooterChange,
}: OrgAccountSelectionProps) {
  const {
    accountAliases,
    accountLookup,
    applyError,
    canAdvanceToLaunch,
    discoveryResult,
    handleTreeSelectionChange,
    hasConnectionErrors,
    isTesting,
    isTestingView,
    isSelectionLocked,
    organizationExternalId,
    selectedCount,
    selectedIdsForTree,
    setAccountAlias,
    showHeaderHelperText,
    totalAccounts,
    treeDataWithConnectionState,
  } = useOrgAccountSelectionFlow({
    onBack,
    onNext,
    onSkip,
    onFooterChange,
  });

  if (!discoveryResult) {
    return (
      <div className="text-muted-foreground py-8 text-center text-sm">
        No discovery data available.
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-5">
      <div className="flex flex-col gap-3">
        <div className="flex items-center gap-4">
          <AWSProviderBadge size={32} />
          <h3 className="text-base font-semibold">My Organization</h3>
        </div>

        <div className="ml-12 flex items-center gap-3">
          <span className="text-text-neutral-tertiary text-xs">UID:</span>
          <div className="bg-bg-neutral-tertiary border-border-input-primary inline-flex h-10 items-center rounded-full border px-4">
            <span className="text-xs font-medium">
              {organizationExternalId || "N/A"}
            </span>
          </div>
        </div>

        {showHeaderHelperText && (
          <p className="text-muted-foreground text-sm">
            {isTestingView
              ? "Testing account connections..."
              : "Confirm all accounts under this Organization you want to add to Prowler."}{" "}
            {!isTestingView &&
              `${selectedCount} of ${totalAccounts} accounts selected.`}
          </p>
        )}
      </div>

      {isTestingView && applyError && (
        <Alert variant="error">
          <AlertTriangle />
          <AlertDescription className="text-text-error-primary">
            {applyError}
          </AlertDescription>
        </Alert>
      )}

      {isTestingView && hasConnectionErrors && !isTesting && (
        <Alert variant="error">
          <AlertTriangle />
          <AlertDescription className="text-text-error-primary">
            {canAdvanceToLaunch
              ? "There was a problem connecting to some accounts. Hover each account to check the error."
              : "No accounts connected successfully. Fix the connection errors and retry before launching scans."}
          </AlertDescription>
        </Alert>
      )}

      <div className="border-border-neutral-secondary min-h-0 flex-1 overflow-y-auto rounded-md border p-2">
        <TreeView
          data={treeDataWithConnectionState}
          showCheckboxes
          enableSelectChildren
          expandAll
          selectedIds={selectedIdsForTree}
          onSelectionChange={
            isSelectionLocked ? () => {} : handleTreeSelectionChange
          }
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
