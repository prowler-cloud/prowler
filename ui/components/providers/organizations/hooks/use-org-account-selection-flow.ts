"use client";

import { useEffect, useRef, useState } from "react";

import { applyDiscovery } from "@/actions/organizations/organizations";
import { buildApplyPayload } from "@/actions/organizations/organizations.adapter";
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
  PROVIDER_SECRET_STATE,
} from "@/types/organizations";
import { TREE_ITEM_STATUS, TreeDataItem } from "@/types/tree";

import {
  buildCandidateToProviderMap,
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
    hierarchy,
    treeData,
    candidateLookup,
    selectableCandidateIds,
    selectableCandidateIdSet,
    selectedCandidateIds,
    candidateAliases,
    createdProviderIds,
    connectionResults,
    connectionErrors,
    setSelectedCandidateIds,
    setCandidateAlias,
    setCreatedProviderIds,
    clearValidationState,
    setConnectionError,
    setConnectionResult,
  } = useOrgSetupStore();

  const [isTestingView, setIsTestingView] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  // Pre-apply credential-replacement warning: apply overwrites the credentials
  // of already-onboarded providers whose registration is `will_replace`.
  const [replaceWarning, setReplaceWarning] = useState<{
    names: string[];
  } | null>(null);
  const replaceConfirmedRef = useRef(false);
  const [candidateToProviderMap, setCandidateToProviderMap] = useState<
    Map<string, string>
  >(new Map());
  const isMountedRef = useRef(true);
  const connectionTestAbortControllerRef = useRef<AbortController | null>(null);
  const hasAppliedRef = useRef(false);
  const lastAppliedSelectionKeyRef = useRef<string>("");
  const startTestingActionRef = useRef<() => void>(() => {});

  const sanitizedSelectedCandidateIds = selectedCandidateIds.filter((id) =>
    selectableCandidateIdSet.has(id),
  );
  const selectedCandidateKey = getSelectionKey(sanitizedSelectedCandidateIds);
  const selectedIdsForTree = buildTreeSelectedIds(
    treeData,
    sanitizedSelectedCandidateIds,
    selectableCandidateIdSet,
  );
  const selectedCandidateIdSet = new Set(sanitizedSelectedCandidateIds);
  const selectedCount = sanitizedSelectedCandidateIds.length;
  const totalCandidates = selectableCandidateIds.length;
  const hasConnectionErrors = Object.values(connectionResults).some(
    (status) => status === CONNECTION_TEST_STATUS.ERROR,
  );
  // Selected candidates whose apply would overwrite an existing provider's
  // credential (registration `will_replace`).
  const willReplaceSelectedNames = sanitizedSelectedCandidateIds
    .map((id) => candidateLookup.get(id))
    .filter(
      (candidate) =>
        candidate?.registration?.provider_secret_state ===
        PROVIDER_SECRET_STATE.WILL_REPLACE,
    )
    .map((candidate) => candidate?.label || candidate?.uid || "")
    .filter((name) => name.length > 0);
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
        selectedCandidateIdSet,
        candidateToProviderMap,
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
    if (!organizationId || !discoveryId || !hierarchy) {
      return;
    }

    setApplyError(null);
    setIsApplying(true);

    const currentSelectedCandidateIds = useOrgSetupStore
      .getState()
      .selectedCandidateIds.filter((id) => selectableCandidateIdSet.has(id));
    const currentSelectionKey = getSelectionKey(currentSelectedCandidateIds);

    // Per-type apply payload, discriminated by the hierarchy being applied: AWS
    // derives OU ancestors client-side; GCP sends projects only (folder
    // ancestors are derived server-side).
    const payload = buildApplyPayload(
      hierarchy,
      currentSelectedCandidateIds,
      candidateAliases,
    );

    const result = await applyDiscovery(organizationId, discoveryId, payload);
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
    const mapping = await buildCandidateToProviderMap({
      selectedCandidateIds: currentSelectedCandidateIds,
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

    setCandidateToProviderMap(mapping);
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
      lastAppliedSelectionKeyRef.current !== selectedCandidateKey;

    if (shouldApplySelection) {
      // Warn before an apply that would overwrite existing provider
      // credentials, unless the user already confirmed this selection.
      if (willReplaceSelectedNames.length > 0 && !replaceConfirmedRef.current) {
        setReplaceWarning({ names: willReplaceSelectedNames });
        return;
      }
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
    const filteredIds = ids.filter((id) => selectableCandidateIdSet.has(id));
    const nextSelectedCandidateKey = getSelectionKey(filteredIds);

    if (nextSelectedCandidateKey !== selectedCandidateKey) {
      hasAppliedRef.current = false;
      lastAppliedSelectionKeyRef.current = "";
      replaceConfirmedRef.current = false;
      setApplyError(null);
      setCandidateToProviderMap(new Map());
      clearValidationState();
    }

    setSelectedCandidateIds(filteredIds);
  };

  const confirmReplaceAndApply = () => {
    replaceConfirmedRef.current = true;
    setReplaceWarning(null);
    startTestingActionRef.current();
  };

  const cancelReplace = () => {
    setReplaceWarning(null);
    setIsTestingView(false);
  };

  return {
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
  };
}
