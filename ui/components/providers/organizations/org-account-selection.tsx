"use client";

import { AlertTriangle } from "lucide-react";

import { WizardFooterConfig } from "@/components/providers/wizard/steps/footer-controls";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal";
import { TreeView } from "@/components/shadcn/tree-view";

import { useOrgAccountSelectionFlow } from "./hooks/use-org-account-selection-flow";
import { OrgAccountTreeItem, TREE_ITEM_MODE } from "./org-account-tree-item";
import { getOrgCandidateNoun, getOrgProviderBadge } from "./org-terminology";

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
    candidateAliases,
    candidateLookup,
    applyError,
    canAdvanceToLaunch,
    hierarchy,
    handleTreeSelectionChange,
    hasConnectionErrors,
    isTesting,
    isTestingView,
    isSelectionLocked,
    organizationExternalId,
    selectedCount,
    selectedIdsForTree,
    setCandidateAlias,
    showHeaderHelperText,
    totalCandidates,
    treeDataWithConnectionState,
    replaceWarning,
    confirmReplaceAndApply,
    cancelReplace,
  } = useOrgAccountSelectionFlow({
    onBack,
    onNext,
    onSkip,
    onFooterChange,
  });

  if (!hierarchy) {
    return (
      <div className="text-muted-foreground py-8 text-center text-sm">
        No discovery data available.
      </div>
    );
  }

  const OrgBadge = getOrgProviderBadge(hierarchy.orgType);
  const noun = getOrgCandidateNoun(hierarchy.orgType);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-5">
      <Modal
        open={replaceWarning !== null}
        scrollable
        onOpenChange={(open) => {
          if (!open) cancelReplace();
        }}
        title="Replace existing credentials?"
        description={`Applying this selection will overwrite the credentials of ${
          replaceWarning?.names.length ?? 0
        } already-onboarded ${
          (replaceWarning?.names.length ?? 0) === 1
            ? noun.singular
            : noun.plural
        }.`}
      >
        {replaceWarning && (
          <div className="flex flex-col gap-4">
            <p className="text-text-neutral-secondary text-sm">
              {replaceWarning.names.length === 1
                ? `The following ${noun.singular} will have its credentials replaced: `
                : `The following ${noun.plural} will have their credentials replaced: `}
              <strong>{replaceWarning.names.join(", ")}</strong>.
            </p>
            <div className="flex w-full justify-end gap-4">
              <Button
                type="button"
                variant="ghost"
                size="lg"
                onClick={cancelReplace}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant="destructive"
                size="lg"
                onClick={confirmReplaceAndApply}
              >
                Replace and continue
              </Button>
            </div>
          </div>
        )}
      </Modal>

      <div className="flex flex-col gap-3">
        <div className="flex items-center gap-4">
          <OrgBadge size={32} />
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
              ? `Testing ${noun.singular} connections...`
              : `Confirm all ${noun.plural} under this Organization you want to add to Prowler.`}{" "}
            {!isTestingView &&
              `${selectedCount} of ${totalCandidates} ${noun.plural} selected.`}
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
              ? `There was a problem connecting to some ${noun.plural}. Hover each ${noun.singular} to check the error.`
              : `No ${noun.plural} connected successfully. Fix the connection errors and retry before launching scans.`}
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
              orgType={hierarchy.orgType}
              candidateLookup={candidateLookup}
              aliases={candidateAliases}
              onAliasChange={setCandidateAlias}
            />
          )}
        />
      </div>
    </div>
  );
}
