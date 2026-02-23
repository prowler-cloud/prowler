"use client";

import { AlertTriangle } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { applyDiscovery } from "@/actions/organizations/organizations";
import {
  buildAccountLookup,
  buildOrgTreeData,
  getOuIdsForSelectedAccounts,
  getSelectableAccountIds,
} from "@/actions/organizations/organizations.adapter";
import {
  checkConnectionProvider,
  getProvider,
} from "@/actions/providers/providers";
import { AWSProviderBadge } from "@/components/icons/providers-badge";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { TreeView } from "@/components/shadcn/tree-view";
import { useOrgSetupStore } from "@/store/organizations/store";
import {
  CONNECTION_TEST_STATUS,
  ConnectionTestStatus,
  DiscoveredAccount,
} from "@/types/organizations";
import { TREE_ITEM_STATUS, TreeDataItem } from "@/types/tree";

import {
  buildAccountToProviderMap,
  canAdvanceToLaunchStep,
  getLaunchableProviderIds,
  pollConnectionTask,
  runWithConcurrencyLimit,
} from "./org-account-selection.utils";
import { OrgAccountTreeItem, TREE_ITEM_MODE } from "./org-account-tree-item";

interface OrgAccountSelectionProps {
  onBack: () => void;
  onNext: () => void;
  onSkip: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

interface SelectionState {
  hasSelectableDescendants: boolean;
  allSelectableDescendantsSelected: boolean;
}

function collectFullySelectedNodeIds(
  node: TreeDataItem,
  selectedAccountIdSet: Set<string>,
  selectableAccountIdSet: Set<string>,
  selectedNodeIds: Set<string>,
): SelectionState {
  if (selectableAccountIdSet.has(node.id)) {
    return {
      hasSelectableDescendants: true,
      allSelectableDescendantsSelected: selectedAccountIdSet.has(node.id),
    };
  }

  const children = node.children ?? [];
  let hasSelectableDescendants = false;
  let allSelectableDescendantsSelected = true;

  for (const child of children) {
    const childSelectionState = collectFullySelectedNodeIds(
      child,
      selectedAccountIdSet,
      selectableAccountIdSet,
      selectedNodeIds,
    );

    if (!childSelectionState.hasSelectableDescendants) {
      continue;
    }

    hasSelectableDescendants = true;
    allSelectableDescendantsSelected =
      allSelectableDescendantsSelected &&
      childSelectionState.allSelectableDescendantsSelected;
  }

  if (hasSelectableDescendants && allSelectableDescendantsSelected) {
    selectedNodeIds.add(node.id);
  }

  return {
    hasSelectableDescendants,
    allSelectableDescendantsSelected,
  };
}

function buildTreeSelectedIds(
  treeData: TreeDataItem[],
  selectedAccountIds: string[],
  selectableAccountIdSet: Set<string>,
): string[] {
  const selectedAccountIdSet = new Set(selectedAccountIds);
  const selectedNodeIds = new Set<string>();

  for (const rootNode of treeData) {
    collectFullySelectedNodeIds(
      rootNode,
      selectedAccountIdSet,
      selectableAccountIdSet,
      selectedNodeIds,
    );
  }

  return [...selectedAccountIds, ...Array.from(selectedNodeIds)];
}

function buildTreeWithConnectionState(
  nodes: TreeDataItem[],
  selectedAccountIdsSet: Set<string>,
  accountToProviderMap: Map<string, string>,
  connectionResults: Record<string, ConnectionTestStatus>,
  connectionErrors: Record<string, string>,
  showPendingState: boolean,
): TreeDataItem[] {
  return nodes.map((node) => {
    const children = node.children
      ? buildTreeWithConnectionState(
          node.children,
          selectedAccountIdsSet,
          accountToProviderMap,
          connectionResults,
          connectionErrors,
          showPendingState,
        )
      : undefined;

    let isLoading = node.isLoading;
    let status = node.status;
    let errorMessage = node.errorMessage;

    if (selectedAccountIdsSet.has(node.id)) {
      const providerId = accountToProviderMap.get(node.id);
      const connectionStatus = providerId
        ? connectionResults[providerId]
        : undefined;

      if (connectionStatus === CONNECTION_TEST_STATUS.SUCCESS) {
        isLoading = false;
        status = TREE_ITEM_STATUS.SUCCESS;
        errorMessage = undefined;
      } else if (connectionStatus === CONNECTION_TEST_STATUS.ERROR) {
        isLoading = false;
        status = TREE_ITEM_STATUS.ERROR;
        errorMessage =
          (providerId && connectionErrors[providerId]) || "Connection failed.";
      } else if (
        showPendingState ||
        connectionStatus === CONNECTION_TEST_STATUS.PENDING
      ) {
        isLoading = true;
        status = undefined;
        errorMessage = undefined;
      }
    }

    return {
      ...node,
      children,
      isLoading,
      status,
      errorMessage,
    };
  });
}

function extractErrorMessage(response: unknown, fallback: string): string {
  if (!response || typeof response !== "object") {
    return fallback;
  }

  const responseRecord = response as {
    error?: string;
    errors?: Array<{ detail?: string }>;
  };
  const detailedError = responseRecord.errors?.[0]?.detail;
  return detailedError || responseRecord.error || fallback;
}

export function OrgAccountSelection({
  onBack,
  onNext,
  onSkip,
  onFooterChange,
}: OrgAccountSelectionProps) {
  const {
    organizationId,
    organizationExternalId,
    discoveryId,
    discoveryResult,
    selectedAccountIds,
    accountAliases,
    createdProviderIds,
    connectionResults,
    connectionErrors,
    setSelectedAccountIds,
    setAccountAlias,
    setCreatedProviderIds,
    setConnectionError,
    setConnectionResult,
  } = useOrgSetupStore();
  const [isTestingView, setIsTestingView] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [accountToProviderMap, setAccountToProviderMap] = useState<
    Map<string, string>
  >(new Map());
  const hasAppliedRef = useRef(false);
  const startTestingActionRef = useRef<() => void>(() => {});

  const treeData = discoveryResult ? buildOrgTreeData(discoveryResult) : [];
  const accountLookup: Map<string, DiscoveredAccount> = discoveryResult
    ? buildAccountLookup(discoveryResult)
    : new Map<string, DiscoveredAccount>();
  const selectableAccountIds = discoveryResult
    ? getSelectableAccountIds(discoveryResult)
    : [];
  const selectableAccountIdSet = new Set(selectableAccountIds);
  const sanitizedSelectedAccountIds = selectedAccountIds.filter((id) =>
    selectableAccountIdSet.has(id),
  );
  const selectedIdsForTree = buildTreeSelectedIds(
    treeData,
    sanitizedSelectedAccountIds,
    selectableAccountIdSet,
  );
  const selectedAccountIdSet = new Set(sanitizedSelectedAccountIds);
  const selectedCount = sanitizedSelectedAccountIds.length;
  const totalAccounts = selectableAccountIds.length;
  const hasConnectionErrors = Object.values(connectionResults).some(
    (status) => status === CONNECTION_TEST_STATUS.ERROR,
  );
  const launchableProviderIds = getLaunchableProviderIds(
    createdProviderIds,
    connectionResults,
  );
  const canAdvanceToLaunch = canAdvanceToLaunchStep(
    createdProviderIds,
    connectionResults,
  );
  const showHeaderHelperText = !isTestingView || isApplying || isTesting;
  const treeDataWithConnectionState = isTestingView
    ? buildTreeWithConnectionState(
        treeData,
        selectedAccountIdSet,
        accountToProviderMap,
        connectionResults,
        connectionErrors,
        isApplying || isTesting,
      )
    : treeData;

  useEffect(() => {
    if (!discoveryResult) {
      return;
    }

    if (sanitizedSelectedAccountIds.length === selectedAccountIds.length) {
      return;
    }

    setSelectedAccountIds(sanitizedSelectedAccountIds);
  }, [
    discoveryResult,
    sanitizedSelectedAccountIds,
    selectedAccountIds,
    setSelectedAccountIds,
  ]);

  const testAllConnections = async (providerIds: string[]) => {
    setIsTesting(true);

    for (const id of providerIds) {
      setConnectionResult(id, CONNECTION_TEST_STATUS.PENDING);
      setConnectionError(id, null);
    }

    await runWithConcurrencyLimit(providerIds, 5, async (providerId) => {
      try {
        const formData = new FormData();
        formData.set("providerId", providerId);

        const checkResult = await checkConnectionProvider(formData);
        if (checkResult?.error || checkResult?.errors?.length) {
          setConnectionResult(providerId, CONNECTION_TEST_STATUS.ERROR);
          setConnectionError(
            providerId,
            extractErrorMessage(checkResult, "Connection test failed."),
          );
          return;
        }

        const taskId = checkResult?.data?.id;
        if (!taskId) {
          setConnectionResult(providerId, CONNECTION_TEST_STATUS.SUCCESS);
          setConnectionError(providerId, null);
          return;
        }

        const taskResult = await pollConnectionTask(taskId);
        setConnectionResult(
          providerId,
          taskResult.success
            ? CONNECTION_TEST_STATUS.SUCCESS
            : CONNECTION_TEST_STATUS.ERROR,
        );
        setConnectionError(
          providerId,
          taskResult.success
            ? null
            : taskResult.error || "Connection failed for this account.",
        );
      } catch {
        setConnectionResult(providerId, CONNECTION_TEST_STATUS.ERROR);
        setConnectionError(
          providerId,
          "Unexpected error during connection test.",
        );
      }
    });

    setIsTesting(false);

    const latestResults = useOrgSetupStore.getState().connectionResults;
    const allPassed =
      providerIds.length > 0 &&
      providerIds.every(
        (providerId) =>
          latestResults[providerId] === CONNECTION_TEST_STATUS.SUCCESS,
      );

    if (allPassed) {
      onNext();
    }
  };

  const handleApplyAndTest = async () => {
    if (!organizationId || !discoveryId || !discoveryResult) {
      return;
    }

    setApplyError(null);
    setIsApplying(true);

    const accounts = sanitizedSelectedAccountIds.map((id) => ({
      id,
      ...(accountAliases[id] ? { alias: accountAliases[id] } : {}),
    }));
    const ouIds = getOuIdsForSelectedAccounts(
      discoveryResult,
      sanitizedSelectedAccountIds,
    );
    const organizationalUnits = ouIds.map((id) => ({ id }));

    const result = await applyDiscovery(
      organizationId,
      discoveryId,
      accounts,
      organizationalUnits,
    );

    if (result?.error || result?.errors?.length) {
      setApplyError(extractErrorMessage(result, "Failed to apply discovery."));
      setIsApplying(false);
      hasAppliedRef.current = false;
      return;
    }

    const providerIds: string[] =
      result.data?.relationships?.providers?.data?.map(
        (provider: { id: string }) => provider.id,
      ) ?? [];

    setCreatedProviderIds(providerIds);
    const mapping = await buildAccountToProviderMap({
      selectedAccountIds: sanitizedSelectedAccountIds,
      providerIds,
      applyResult: result,
      resolveProviderUidById: async (providerId) => {
        const providerFormData = new FormData();
        providerFormData.set("id", providerId);
        const providerResponse = await getProvider(providerFormData);

        if (providerResponse?.error || providerResponse?.errors?.length) {
          return null;
        }

        return typeof providerResponse?.data?.attributes?.uid === "string"
          ? providerResponse.data.attributes.uid
          : null;
      },
    });
    setAccountToProviderMap(mapping);
    setIsApplying(false);

    await testAllConnections(providerIds);
  };

  const handleStartTesting = () => {
    setIsTestingView(true);

    if (applyError) {
      setApplyError(null);
      hasAppliedRef.current = false;
    }

    if (!hasAppliedRef.current) {
      hasAppliedRef.current = true;
      void handleApplyAndTest();
      return;
    }

    const failedProviderIds = createdProviderIds.filter(
      (providerId) =>
        connectionResults[providerId] === CONNECTION_TEST_STATUS.ERROR,
    );
    const providerIdsToTest =
      failedProviderIds.length > 0 ? failedProviderIds : createdProviderIds;
    void testAllConnections(providerIdsToTest);
  };
  startTestingActionRef.current = handleStartTesting;

  useEffect(() => {
    if (!isTestingView) {
      onFooterChange({
        showBack: true,
        backLabel: "Back",
        onBack,
        showSecondaryAction: false,
        secondaryActionLabel: "",
        secondaryActionVariant: "outline",
        secondaryActionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
        showAction: true,
        actionLabel: "Test Connections",
        actionDisabled: selectedCount === 0,
        actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
        onAction: () => {
          startTestingActionRef.current();
        },
      });
      return;
    }

    const canRetry = hasConnectionErrors || Boolean(applyError);

    onFooterChange({
      showBack: true,
      backLabel: "Back",
      backDisabled: isApplying || isTesting,
      onBack: () => setIsTestingView(false),
      showSecondaryAction: true,
      secondaryActionLabel: "Skip Connection Validation",
      secondaryActionDisabled: isApplying || isTesting || !canAdvanceToLaunch,
      secondaryActionVariant: "link",
      secondaryActionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onSecondaryAction: () => {
        setCreatedProviderIds(launchableProviderIds);
        onSkip();
      },
      showAction: isApplying || isTesting || canRetry,
      actionLabel: "Test Connections",
      actionDisabled: isApplying || isTesting || !canRetry,
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: canRetry
        ? () => {
            startTestingActionRef.current();
          }
        : undefined,
    });
  }, [
    applyError,
    connectionErrors,
    hasConnectionErrors,
    isApplying,
    isTesting,
    isTestingView,
    launchableProviderIds,
    onBack,
    onFooterChange,
    onSkip,
    selectedCount,
    canAdvanceToLaunch,
    setConnectionError,
    setCreatedProviderIds,
  ]);

  const handleTreeSelectionChange = (ids: string[]) => {
    setSelectedAccountIds(ids.filter((id) => selectableAccountIdSet.has(id)));
  };

  if (!discoveryResult) {
    return (
      <div className="text-muted-foreground py-8 text-center text-sm">
        No discovery data available.
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-5">
      {/* Header */}
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

      {/* Tree */}
      <div className="border-border-neutral-secondary min-h-0 flex-1 overflow-y-auto rounded-md border p-2">
        <TreeView
          data={treeDataWithConnectionState}
          showCheckboxes
          enableSelectChildren
          expandAll
          selectedIds={selectedIdsForTree}
          onSelectionChange={
            isTestingView ? () => {} : handleTreeSelectionChange
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
