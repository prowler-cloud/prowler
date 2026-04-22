"use client";

import { useEffect, useRef, useState } from "react";

import { applyDiscovery } from "@/actions/organizations/organizations";
import { getOuIdsForSelectedAccounts } from "@/actions/organizations/organizations.adapter";
import {
  checkConnectionProvider,
  getProvider,
} from "@/actions/providers/providers";
import {
  WIZARD_FOOTER_ACTION_TYPE,
  WizardFooterConfig,
} from "@/components/providers/wizard/steps/footer-controls";
import { useOrgSetupStore } from "@/store/organizations/store";
import {
  CONNECTION_TEST_STATUS,
  ConnectionTestStatus,
} from "@/types/organizations";
import { TREE_ITEM_STATUS, TreeDataItem } from "@/types/tree";

import {
  buildAccountToProviderMap,
  canAdvanceToLaunchStep,
  getLaunchableProviderIds,
  pollConnectionTask,
  runWithConcurrencyLimit,
} from "../org-account-selection.utils";
import { extractErrorMessage } from "./error-utils";

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

function getSelectionKey(ids: string[]) {
  return [...ids].sort().join(",");
}

interface UseOrgAccountSelectionFlowProps {
  onBack: () => void;
  onNext: () => void;
  onSkip: () => void;
  onFooterChange: (config: WizardFooterConfig) => void;
}

export function useOrgAccountSelectionFlow({
  onBack,
  onNext,
  onSkip,
  onFooterChange,
}: UseOrgAccountSelectionFlowProps) {
  const {
    organizationId,
    organizationExternalId,
    discoveryId,
    discoveryResult,
    treeData,
    accountLookup,
    selectableAccountIds,
    selectableAccountIdSet,
    selectedAccountIds,
    accountAliases,
    createdProviderIds,
    connectionResults,
    connectionErrors,
    setSelectedAccountIds,
    setAccountAlias,
    setCreatedProviderIds,
    clearValidationState,
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
  const isMountedRef = useRef(true);
  const connectionTestAbortControllerRef = useRef<AbortController | null>(null);
  const hasAppliedRef = useRef(false);
  const lastAppliedSelectionKeyRef = useRef<string>("");
  const startTestingActionRef = useRef<() => void>(() => {});

  const sanitizedSelectedAccountIds = selectedAccountIds.filter((id) =>
    selectableAccountIdSet.has(id),
  );
  const selectedAccountKey = getSelectionKey(sanitizedSelectedAccountIds);
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
  const isSelectionLocked = isApplying || isTesting;
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
    isMountedRef.current = true;

    return () => {
      isMountedRef.current = false;
      connectionTestAbortControllerRef.current?.abort();
    };
  }, []);

  const testAllConnections = async (providerIds: string[]) => {
    connectionTestAbortControllerRef.current?.abort();
    const abortController = new AbortController();
    connectionTestAbortControllerRef.current = abortController;
    const { signal } = abortController;

    setIsTesting(true);

    for (const id of providerIds) {
      setConnectionResult(id, CONNECTION_TEST_STATUS.PENDING);
      setConnectionError(id, null);
    }

    try {
      await runWithConcurrencyLimit(providerIds, 5, async (providerId) => {
        if (!isMountedRef.current || signal.aborted) {
          return;
        }

        try {
          const formData = new FormData();
          formData.set("providerId", providerId);

          const checkResult = await checkConnectionProvider(formData);
          if (!isMountedRef.current || signal.aborted) {
            return;
          }

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

          const taskResult = await pollConnectionTask(taskId, { signal });
          if (!isMountedRef.current || signal.aborted) {
            return;
          }
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
          if (!isMountedRef.current || signal.aborted) {
            return;
          }
          setConnectionResult(providerId, CONNECTION_TEST_STATUS.ERROR);
          setConnectionError(
            providerId,
            "Unexpected error during connection test.",
          );
        }
      });
    } finally {
      if (connectionTestAbortControllerRef.current === abortController) {
        connectionTestAbortControllerRef.current = null;
        if (isMountedRef.current) {
          setIsTesting(false);
        }
      }
    }

    if (!isMountedRef.current || signal.aborted) {
      return;
    }

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

    const currentSelectedAccountIds = useOrgSetupStore
      .getState()
      .selectedAccountIds.filter((id) => selectableAccountIdSet.has(id));
    const currentSelectionKey = getSelectionKey(currentSelectedAccountIds);

    const accounts = currentSelectedAccountIds.map((id) => ({
      id,
      ...(accountAliases[id] ? { alias: accountAliases[id] } : {}),
    }));
    const ouIds = getOuIdsForSelectedAccounts(
      discoveryResult,
      currentSelectedAccountIds,
    );
    const organizationalUnits = ouIds.map((id) => ({ id }));

    const result = await applyDiscovery(
      organizationId,
      discoveryId,
      accounts,
      organizationalUnits,
    );
    if (!isMountedRef.current) {
      return;
    }

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
      selectedAccountIds: currentSelectedAccountIds,
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
    if (!isMountedRef.current) {
      return;
    }

    setAccountToProviderMap(mapping);
    setIsApplying(false);
    lastAppliedSelectionKeyRef.current = currentSelectionKey;

    await testAllConnections(providerIds);
  };

  const handleStartTesting = () => {
    setIsTestingView(true);

    if (applyError) {
      setApplyError(null);
      hasAppliedRef.current = false;
      lastAppliedSelectionKeyRef.current = "";
    }

    const shouldApplySelection =
      !hasAppliedRef.current ||
      lastAppliedSelectionKeyRef.current !== selectedAccountKey;

    if (shouldApplySelection) {
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
    const hasSelectedAccounts = selectedCount > 0;

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
      showAction: isApplying || isTesting || canRetry || hasSelectedAccounts,
      actionLabel: "Test Connections",
      actionDisabled: isApplying || isTesting || !hasSelectedAccounts,
      actionType: WIZARD_FOOTER_ACTION_TYPE.BUTTON,
      onAction: hasSelectedAccounts
        ? () => {
            startTestingActionRef.current();
          }
        : undefined,
    });
  }, [
    applyError,
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
    setCreatedProviderIds,
  ]);

  const handleTreeSelectionChange = (ids: string[]) => {
    const filteredIds = ids.filter((id) => selectableAccountIdSet.has(id));
    const nextSelectedAccountKey = getSelectionKey(filteredIds);

    if (nextSelectedAccountKey !== selectedAccountKey) {
      hasAppliedRef.current = false;
      lastAppliedSelectionKeyRef.current = "";
      setApplyError(null);
      setAccountToProviderMap(new Map());
      clearValidationState();
    }

    setSelectedAccountIds(filteredIds);
  };

  return {
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
  };
}
