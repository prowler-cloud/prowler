"use client";

import { AlertTriangle, Loader2, RefreshCw } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { applyDiscovery } from "@/actions/organizations/organizations";
import {
  buildAccountLookup,
  buildOrgTreeData,
  getOuIdsForSelectedAccounts,
} from "@/actions/organizations/organizations.adapter";
import { checkConnectionProvider } from "@/actions/providers/providers";
import { Badge, Button } from "@/components/shadcn";
import { TreeView } from "@/components/shadcn/tree-view";
import { checkTaskStatus } from "@/lib";
import { useOrgSetupStore } from "@/store/organizations/store";
import { CONNECTION_TEST_STATUS } from "@/types/organizations";

import { OrgAccountTreeItem, TREE_ITEM_MODE } from "./org-account-tree-item";

interface OrgConnectionTestProps {
  onBack: () => void;
  onNext: () => void;
  onSkip: () => void;
}

export function OrgConnectionTest({
  onBack,
  onNext,
  onSkip,
}: OrgConnectionTestProps) {
  const {
    organizationId,
    organizationName,
    organizationExternalId,
    discoveryId,
    discoveryResult,
    selectedAccountIds,
    accountAliases,
    createdProviderIds,
    connectionResults,
    setCreatedProviderIds,
    setConnectionResult,
  } = useOrgSetupStore();

  const [isApplying, setIsApplying] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [accountToProviderMap, setAccountToProviderMap] = useState<
    Map<string, string>
  >(new Map());

  const hasApplied = useRef(false);

  // On mount: apply discovery, then test connections
  useEffect(() => {
    if (hasApplied.current) return;
    hasApplied.current = true;
    handleApplyAndTest();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleApplyAndTest = async () => {
    if (!organizationId || !discoveryId || !discoveryResult) return;

    setIsApplying(true);
    setApplyError(null);

    // Build apply payload
    const accounts = selectedAccountIds.map((id) => ({
      id,
      ...(accountAliases[id] ? { alias: accountAliases[id] } : {}),
    }));

    const ouIds = getOuIdsForSelectedAccounts(
      discoveryResult,
      selectedAccountIds,
    );
    const organizationalUnits = ouIds.map((id) => ({ id }));

    const result = await applyDiscovery(
      organizationId,
      discoveryId,
      accounts,
      organizationalUnits,
    );

    if (result?.error) {
      setApplyError(result.error);
      setIsApplying(false);
      return;
    }

    // Extract created provider IDs from relationships
    const providerIds: string[] =
      result.data?.relationships?.providers?.data?.map(
        (p: { id: string }) => p.id,
      ) ?? [];

    setCreatedProviderIds(providerIds);

    // Build account -> provider mapping
    // The providers are returned in the same order as the accounts submitted
    const mapping = new Map<string, string>();
    selectedAccountIds.forEach((accountId, index) => {
      if (providerIds[index]) {
        mapping.set(accountId, providerIds[index]);
      }
    });
    setAccountToProviderMap(mapping);

    setIsApplying(false);

    // Now test all connections
    await testAllConnections(providerIds);
  };

  const testAllConnections = async (providerIds: string[]) => {
    setIsTesting(true);

    // Initialize all as pending
    for (const id of providerIds) {
      setConnectionResult(id, CONNECTION_TEST_STATUS.PENDING);
    }

    // Test all concurrently
    const testPromises = providerIds.map(async (providerId) => {
      try {
        const formData = new FormData();
        formData.set("providerId", providerId);

        const checkResult = await checkConnectionProvider(formData);

        if (checkResult?.error) {
          setConnectionResult(providerId, CONNECTION_TEST_STATUS.ERROR);
          return;
        }

        // Poll for task completion
        const taskId = checkResult?.data?.id;
        if (taskId) {
          const taskResult = await checkTaskStatus(taskId);
          setConnectionResult(
            providerId,
            taskResult.completed
              ? CONNECTION_TEST_STATUS.SUCCESS
              : CONNECTION_TEST_STATUS.ERROR,
          );
        } else {
          // No task returned — consider it success (connection already verified)
          setConnectionResult(providerId, CONNECTION_TEST_STATUS.SUCCESS);
        }
      } catch {
        setConnectionResult(providerId, CONNECTION_TEST_STATUS.ERROR);
      }
    });

    await Promise.allSettled(testPromises);
    setIsTesting(false);

    // Check if all passed — auto-advance
    const allResults = useOrgSetupStore.getState().connectionResults;
    const allPassed = providerIds.every(
      (id) => allResults[id] === CONNECTION_TEST_STATUS.SUCCESS,
    );
    if (allPassed && providerIds.length > 0) {
      onNext();
    }
  };

  const handleRetryFailed = () => {
    const failedProviderIds = createdProviderIds.filter(
      (id) => connectionResults[id] === CONNECTION_TEST_STATUS.ERROR,
    );
    testAllConnections(failedProviderIds);
  };

  if (!discoveryResult) return null;

  const treeData = buildOrgTreeData(discoveryResult);
  const accountLookup = buildAccountLookup(discoveryResult);

  const hasErrors = Object.values(connectionResults).some(
    (s) => s === CONNECTION_TEST_STATUS.ERROR,
  );

  return (
    <div className="flex flex-col gap-5">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Badge variant="outline">AWS</Badge>
        <span className="text-sm font-medium">{organizationName}</span>
        {organizationExternalId && (
          <Badge variant="secondary">{organizationExternalId}</Badge>
        )}
      </div>

      {/* Apply error */}
      {applyError && (
        <div className="border-destructive/50 bg-destructive/10 text-destructive rounded-md border px-4 py-3 text-sm">
          {applyError}
        </div>
      )}

      {/* Applying state */}
      {isApplying && (
        <div className="flex items-center gap-3 py-8">
          <Loader2 className="text-primary size-5 animate-spin" />
          <span className="text-sm">
            Applying discovery results and creating providers...
          </span>
        </div>
      )}

      {/* Connection test error banner */}
      {hasErrors && !isTesting && (
        <div className="border-destructive/50 bg-destructive/10 text-destructive flex items-start gap-3 rounded-md border px-4 py-3 text-sm">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>
            There was a problem connecting to some accounts. Ensure the Prowler
            StackSet has successfully deployed then retry testing connections.
          </span>
        </div>
      )}

      {/* Tree with test results */}
      {!isApplying && !applyError && (
        <div className="max-h-80 overflow-y-auto rounded-md border p-2">
          <TreeView
            data={treeData}
            expandAll
            selectedIds={selectedAccountIds}
            renderItem={(params) => (
              <OrgAccountTreeItem
                params={params}
                mode={TREE_ITEM_MODE.TESTING}
                accountLookup={accountLookup}
                aliases={accountAliases}
                connectionResults={connectionResults}
                accountToProviderMap={accountToProviderMap}
              />
            )}
          />
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-between">
        <Button type="button" variant="ghost" onClick={onBack}>
          Back
        </Button>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onSkip}
            className="text-muted-foreground hover:text-foreground text-sm underline"
          >
            Skip Connection Validation
          </button>

          {hasErrors && !isTesting && (
            <Button type="button" onClick={handleRetryFailed}>
              <RefreshCw className="mr-2 size-4" />
              Test Connections
            </Button>
          )}

          {isTesting && (
            <Button disabled>
              <Loader2 className="mr-2 size-4 animate-spin" />
              Testing...
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
