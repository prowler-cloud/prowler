"use client";

import { Check } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import {
  addRegistryArtifact,
  disconnectRegistryCredential,
  refreshRegistryCollections,
  removeRegistryArtifact,
  submitRegistryCredential,
} from "@/actions/registry/registry";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn/tabs/tabs";
import { toast } from "@/components/shadcn/toast/use-toast";
import {
  REGISTRY_BOOTSTRAP_STATE,
  REGISTRY_CATALOG,
  REGISTRY_CREDENTIAL_ACTION,
  REGISTRY_FAILURE,
  REGISTRY_MUTATION,
  type RegistryBootstrapState,
  type RegistryMutationResult,
} from "@/types/registry";

import { RegistryAccessDialog } from "./registry-access-dialog";
import {
  RegistryArtifactCard,
  RegistryTenantArtifactCard,
} from "./registry-artifact-card";
import { RegistryArtifactGrid } from "./registry-artifact-grid";
import { RegistryCredentialBanner } from "./registry-credential-banner";
import { useRegistryEligibility } from "./registry-eligibility-provider";
import {
  buildRegistryMarketplaceModel,
  REGISTRY_MARKETPLACE_SORT,
  type RegistryExplorerFilters,
  type RegistryMarketplaceSort,
} from "./registry-explorer.model";
import { RegistryRemoveDialog } from "./registry-remove-dialog";
import { RegistryToolbar } from "./registry-toolbar";

const PAGE_SUBTITLE =
  "Discover and install checks, compliance frameworks, and providers for your workspace.";

const REGISTRY_TAB = { EXPLORE: "explore", MINE: "mine" } as const;
type RegistryTab = (typeof REGISTRY_TAB)[keyof typeof REGISTRY_TAB];

const REGISTRY_PENDING_OPERATION = {
  CREDENTIAL: "credential",
  REMOVE: "remove",
} as const;
type RegistryPendingOperation =
  (typeof REGISTRY_PENDING_OPERATION)[keyof typeof REGISTRY_PENDING_OPERATION];

const REGISTRY_ACCESS_DIALOG_MODE = {
  CONNECT: "connect",
  MANAGE: "manage",
} as const;
type RegistryAccessDialogMode =
  (typeof REGISTRY_ACCESS_DIALOG_MODE)[keyof typeof REGISTRY_ACCESS_DIALOG_MODE];

interface RetryStateProps {
  title: string;
  children: string;
}

function RetryState({ title, children }: RetryStateProps) {
  return (
    <section aria-live="polite" className="mx-auto max-w-2xl py-12 text-center">
      <h1 className="text-xl font-semibold">{title}</h1>
      <p className="text-text-neutral-secondary mt-3 text-sm">{children}</p>
      <div className="mt-6">
        <Button onClick={() => window.location.reload()}>Retry</Button>
      </div>
    </section>
  );
}

function mutationFailureMessage(result: RegistryMutationResult) {
  if (result.status === REGISTRY_MUTATION.REFUSED) return result.message;
  if (result.status === REGISTRY_MUTATION.REFRESH_FAILED) {
    return "Registry membership could not be confirmed. Try again.";
  }
  return "The Registry operation could not be completed. Try again.";
}

interface RegistryExplorerProps {
  initialState: RegistryBootstrapState;
}

export function RegistryExplorer({ initialState }: RegistryExplorerProps) {
  // Access invalidation unmounts this component, clearing every local snapshot.
  const { invalidate } = useRegistryEligibility();
  const [state, setState] = useState(initialState);
  const [filters, setFilters] = useState<RegistryExplorerFilters>({});
  const [sort, setSort] = useState<RegistryMarketplaceSort>(
    REGISTRY_MARKETPLACE_SORT.NAME,
  );
  const [activeTab, setActiveTab] = useState<RegistryTab>(REGISTRY_TAB.EXPLORE);
  const [pendingOperation, setPendingOperation] =
    useState<RegistryPendingOperation | null>(null);
  const [pendingAddName, setPendingAddName] = useState<string>();
  const [accessDialogMode, setAccessDialogMode] =
    useState<RegistryAccessDialogMode>();
  const [removeTarget, setRemoveTarget] = useState<string>();
  const [operationMessage, setOperationMessage] = useState<string>();
  const connectButtonRef = useRef<HTMLButtonElement>(null);
  const manageButtonRef = useRef<HTMLButtonElement>(null);
  const removeTriggerRef = useRef<HTMLButtonElement | null>(null);
  const operationGeneration = useRef(0);

  useEffect(
    () => () => {
      operationGeneration.current += 1;
    },
    [],
  );

  async function handleAdd(normalizedName: string) {
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingAddName(normalizedName);
    const result = await addRegistryArtifact({ normalizedName });
    if (generation !== operationGeneration.current) return;
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED) return invalidate();

    setPendingAddName(undefined);
    if (result.status !== REGISTRY_MUTATION.CONFIRMED) {
      setOperationMessage(mutationFailureMessage(result));
      return;
    }

    setState((current) =>
      current.status === REGISTRY_BOOTSTRAP_STATE.READY
        ? { ...current, tenantArtifacts: result.tenantArtifacts }
        : current,
    );
    toast({ title: "Artifact added" });
  }

  async function handleCredentialSubmit(key: string) {
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingOperation(REGISTRY_PENDING_OPERATION.CREDENTIAL);
    const result = await submitRegistryCredential(key);
    if (generation !== operationGeneration.current) return;
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED) return invalidate();

    if (result.status === REGISTRY_CREDENTIAL_ACTION.CONNECTED) {
      const collections = await refreshRegistryCollections();
      if (generation !== operationGeneration.current) return;
      if (collections.status === REGISTRY_FAILURE.ACCESS_DENIED) {
        return invalidate();
      }
      setPendingOperation(null);
      if (collections.status === REGISTRY_CATALOG.COMPLETE) {
        setAccessDialogMode(undefined);
        setState({
          status: REGISTRY_BOOTSTRAP_STATE.READY,
          credential: result.credential,
          catalog: collections.catalog,
          tenantArtifacts: collections.tenantArtifacts,
        });
        return;
      }
      setOperationMessage(
        "Registry collections could not be loaded. Try again.",
      );
      return;
    }

    setPendingOperation(null);
    if (
      result.status === REGISTRY_CREDENTIAL_ACTION.PENDING ||
      result.status === REGISTRY_CREDENTIAL_ACTION.INVALID
    ) {
      setAccessDialogMode(undefined);
      setState((current) =>
        current.status === REGISTRY_BOOTSTRAP_STATE.ONBOARDING ||
        current.status === REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
          ? {
              status:
                result.status === REGISTRY_CREDENTIAL_ACTION.PENDING
                  ? REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
                  : REGISTRY_BOOTSTRAP_STATE.ONBOARDING,
              credential: result.credential,
              tenantArtifacts: current.tenantArtifacts,
            }
          : current,
      );
      return;
    }

    setOperationMessage(
      result.status === REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED
        ? "Registry key validation failed. Existing access is unchanged."
        : "Registry key validation could not be completed. Try again.",
    );
  }

  async function handleDisconnect() {
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingOperation(REGISTRY_PENDING_OPERATION.CREDENTIAL);
    const result = await disconnectRegistryCredential();
    if (generation !== operationGeneration.current) return;
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED) return invalidate();

    setPendingOperation(null);
    if (result.status !== REGISTRY_CREDENTIAL_ACTION.DISCONNECTED) {
      setOperationMessage(
        "Registry access could not be disconnected. Try again.",
      );
      return;
    }

    setAccessDialogMode(undefined);
    setState({
      status: REGISTRY_BOOTSTRAP_STATE.ONBOARDING,
      credential: result.credential,
      tenantArtifacts: result.tenantArtifacts,
    });
  }

  async function handleRemove(normalizedName: string) {
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingOperation(REGISTRY_PENDING_OPERATION.REMOVE);
    const result = await removeRegistryArtifact(normalizedName);
    if (generation !== operationGeneration.current) return;
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED) return invalidate();

    setPendingOperation(null);
    if (result.status !== REGISTRY_MUTATION.CONFIRMED) {
      setOperationMessage(mutationFailureMessage(result));
      return;
    }

    setRemoveTarget(undefined);
    setState((current) =>
      current.status === REGISTRY_BOOTSTRAP_STATE.READY
        ? { ...current, tenantArtifacts: result.tenantArtifacts }
        : current,
    );
    toast({ title: "Artifact removed" });
  }

  function openRemoveDialog(
    normalizedName: string,
    trigger: HTMLButtonElement | null,
  ) {
    removeTriggerRef.current = trigger;
    setRemoveTarget(normalizedName);
  }

  const accessDialogProps = {
    errorMessage: operationMessage,
    onOpenChange: (open: boolean) => {
      if (!open && pendingOperation !== REGISTRY_PENDING_OPERATION.CREDENTIAL) {
        setAccessDialogMode(undefined);
      }
    },
    onSubmit: handleCredentialSubmit,
    open: true,
    pending: pendingOperation === REGISTRY_PENDING_OPERATION.CREDENTIAL,
    returnFocusRef:
      accessDialogMode === REGISTRY_ACCESS_DIALOG_MODE.CONNECT
        ? connectButtonRef
        : manageButtonRef,
  };
  const accessDialog =
    accessDialogMode === REGISTRY_ACCESS_DIALOG_MODE.CONNECT ? (
      <RegistryAccessDialog mode="connect" {...accessDialogProps} />
    ) : accessDialogMode === REGISTRY_ACCESS_DIALOG_MODE.MANAGE ? (
      <RegistryAccessDialog
        mode="manage"
        onDisconnect={handleDisconnect}
        {...accessDialogProps}
      />
    ) : null;

  if (
    state.status === REGISTRY_BOOTSTRAP_STATE.ONBOARDING ||
    state.status === REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
  ) {
    return (
      <div className="space-y-6">
        <p className="text-text-neutral-secondary text-sm">{PAGE_SUBTITLE}</p>
        {!accessDialogMode && operationMessage && (
          <p role="alert">{operationMessage}</p>
        )}
        <RegistryCredentialBanner
          connectButtonRef={connectButtonRef}
          onConnect={() =>
            setAccessDialogMode(REGISTRY_ACCESS_DIALOG_MODE.CONNECT)
          }
          tenantArtifactCount={state.tenantArtifacts.length}
          validationPending={
            state.status === REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
          }
        />
        {accessDialog}
      </div>
    );
  }
  if (state.status !== REGISTRY_BOOTSTRAP_STATE.READY) {
    const messages = {
      [REGISTRY_BOOTSTRAP_STATE.INCOMPLETE]: [
        "Registry catalog is incomplete",
        "Complete catalog controls and metrics are unavailable until every catalog page loads. Retry to load the catalog again.",
      ],
      [REGISTRY_BOOTSTRAP_STATE.UNAVAILABLE]: [
        "Registry is unavailable",
        "Registry data may be stale or unavailable. Retry when the service is available.",
      ],
      [REGISTRY_BOOTSTRAP_STATE.RECONNECT]: [
        "Reconnect Registry",
        "Reconnect Registry before exploring artifacts.",
      ],
      [REGISTRY_BOOTSTRAP_STATE.ERROR]: [
        "Registry could not be loaded",
        "An unexpected Registry error occurred. Retry to load the explorer again.",
      ],
    } as const;
    const [title, message] = messages[state.status];
    return <RetryState title={title}>{message}</RetryState>;
  }

  const model = buildRegistryMarketplaceModel(
    state.catalog,
    state.tenantArtifacts,
    filters,
    sort,
  );
  if (!model.isComplete) {
    return (
      <RetryState title="Registry catalog is incomplete">
        Complete catalog controls and metrics are unavailable.
      </RetryState>
    );
  }
  return (
    <div className="space-y-6">
      <h1 className="sr-only">Registry marketplace</h1>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <p className="text-text-neutral-secondary text-sm">{PAGE_SUBTITLE}</p>
        <div className="flex items-center gap-3">
          <Badge variant="success">
            <Check aria-hidden />
            API key connected
          </Badge>
          <Button
            onClick={() =>
              setAccessDialogMode(REGISTRY_ACCESS_DIALOG_MODE.MANAGE)
            }
            ref={manageButtonRef}
            type="button"
            variant="outline"
          >
            Manage access
          </Button>
        </div>
      </div>
      {!accessDialogMode && operationMessage && (
        <p role="alert">{operationMessage}</p>
      )}
      <Tabs
        onValueChange={(value) => setActiveTab(value as RegistryTab)}
        value={activeTab}
      >
        <div className="border-border-neutral-secondary border-b">
          <TabsList>
            <TabsTrigger
              adornment={
                <Badge size="sm" variant="tag">
                  {state.catalog.artifacts.length}
                </Badge>
              }
              value={REGISTRY_TAB.EXPLORE}
            >
              Explore
            </TabsTrigger>
            <TabsTrigger
              adornment={
                <Badge size="sm" variant="tag">
                  {state.tenantArtifacts.length}
                </Badge>
              }
              value={REGISTRY_TAB.MINE}
            >
              My artifacts
            </TabsTrigger>
          </TabsList>
        </div>
        <TabsContent className="space-y-4 pt-4" value={REGISTRY_TAB.EXPLORE}>
          <RegistryToolbar
            filters={filters}
            onFiltersChange={setFilters}
            onSortChange={setSort}
            providers={model.providers}
            resultsCount={model.artifacts.length}
            sort={sort}
          />
          <RegistryArtifactGrid
            emptyMessage={
              state.catalog.artifacts.length === 0
                ? "No Registry artifacts are available."
                : "No artifacts match the current filters."
            }
            isEmpty={model.artifacts.length === 0}
          >
            {model.artifacts.map((artifact) => (
              <li key={artifact.normalizedName}>
                <RegistryArtifactCard
                  artifact={artifact}
                  isAddPending={pendingAddName === artifact.normalizedName}
                  onAdd={() => handleAdd(artifact.normalizedName)}
                  onRemove={(trigger) =>
                    openRemoveDialog(artifact.normalizedName, trigger)
                  }
                />
              </li>
            ))}
          </RegistryArtifactGrid>
        </TabsContent>
        <TabsContent className="space-y-4 pt-4" value={REGISTRY_TAB.MINE}>
          <RegistryArtifactGrid
            emptyMessage="No artifacts in this workspace yet."
            isEmpty={model.myArtifacts.length === 0}
          >
            {model.myArtifacts.map((myArtifact) => (
              <li key={myArtifact.normalizedName}>
                {myArtifact.catalogArtifact ? (
                  <RegistryArtifactCard
                    artifact={myArtifact.catalogArtifact}
                    isAddPending={pendingAddName === myArtifact.normalizedName}
                    onAdd={() => handleAdd(myArtifact.normalizedName)}
                    onRemove={(trigger) =>
                      openRemoveDialog(myArtifact.normalizedName, trigger)
                    }
                  />
                ) : (
                  <RegistryTenantArtifactCard
                    normalizedName={myArtifact.normalizedName}
                    onRemove={(trigger) =>
                      openRemoveDialog(myArtifact.normalizedName, trigger)
                    }
                    versionSpec={myArtifact.versionSpec}
                  />
                )}
              </li>
            ))}
          </RegistryArtifactGrid>
        </TabsContent>
      </Tabs>
      {accessDialog}
      <RegistryRemoveDialog
        artifactName={removeTarget}
        isPending={pendingOperation === REGISTRY_PENDING_OPERATION.REMOVE}
        onConfirm={() => removeTarget && handleRemove(removeTarget)}
        onOpenChange={(open) => {
          if (!open && pendingOperation !== REGISTRY_PENDING_OPERATION.REMOVE)
            setRemoveTarget(undefined);
        }}
        open={removeTarget !== undefined}
        returnFocusRef={removeTriggerRef}
      />
    </div>
  );
}
