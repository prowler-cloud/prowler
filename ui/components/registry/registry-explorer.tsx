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
  REGISTRY_MUTATION,
  type RegistryBootstrapState,
  type RegistryMutationResult,
} from "@/types/registry";

import { RegistryAccessDialog } from "./registry-access-dialog";
import {
  RegistryArtifactCard,
  RegistryTenantArtifactCard,
} from "./registry-artifact-card";
import { RegistryArtifactDetail } from "./registry-artifact-detail";
import { RegistryArtifactGrid } from "./registry-artifact-grid";
import { RegistryArtifactPanel } from "./registry-artifact-panel";
import { RegistryCredentialBanner } from "./registry-credential-banner";
import {
  buildRegistryMarketplaceModel,
  getRegistryArtifactDetail,
  REGISTRY_MARKETPLACE_SORT,
  type RegistryExplorerFilters,
  type RegistryMarketplaceSort,
} from "./registry-explorer.model";
import { RegistryRemoveDialog } from "./registry-remove-dialog";
import { RegistryToolbar } from "./registry-toolbar";

const PAGE_SUBTITLE =
  "Discover and install checks, compliance frameworks, and providers for your workspace.";

function RetryState({ title, children }: { title: string; children: string }) {
  return (
    <section aria-live="polite" className="mx-auto max-w-2xl py-12 text-center">
      <h1 className="text-xl font-semibold">{title}</h1>
      <p className="text-text-neutral-secondary mt-3 text-sm">{children}</p>
      <Button className="mt-6" onClick={() => window.location.reload()}>
        Retry
      </Button>
    </section>
  );
}

function mutationFailureMessage(result: RegistryMutationResult) {
  if (result.status === REGISTRY_MUTATION.REFUSED) return result.message;
  if (result.status === REGISTRY_MUTATION.REFRESH_FAILED) {
    return "Registry membership could not be confirmed. Try again.";
  }
  if (result.status === "access_denied") {
    return "Registry access is no longer available.";
  }
  return "The Registry operation could not be completed. Try again.";
}

interface RegistryExplorerProps {
  initialState: RegistryBootstrapState;
}

export function RegistryExplorer({ initialState }: RegistryExplorerProps) {
  // Access invalidation unmounts this component, clearing every local snapshot.
  const [state, setState] = useState(initialState);
  const [filters, setFilters] = useState<RegistryExplorerFilters>({});
  const [sort, setSort] = useState<RegistryMarketplaceSort>(
    REGISTRY_MARKETPLACE_SORT.NAME,
  );
  const [activeTab, setActiveTab] = useState<"explore" | "mine">("explore");
  const [selectedName, setSelectedName] = useState<string>();
  const [pendingOperation, setPendingOperation] = useState<
    "add" | "credential" | "remove" | null
  >(null);
  const [accessDialogMode, setAccessDialogMode] = useState<
    "connect" | "manage"
  >();
  const [removeTarget, setRemoveTarget] = useState<string>();
  const [operationMessage, setOperationMessage] = useState<string>();
  const detailHeadingRef = useRef<HTMLHeadingElement>(null);
  const connectButtonRef = useRef<HTMLButtonElement>(null);
  const manageButtonRef = useRef<HTMLButtonElement>(null);
  const removeButtonRef = useRef<HTMLButtonElement>(null);
  const panelTriggerRef = useRef<HTMLElement | null>(null);
  const operationGeneration = useRef(0);

  useEffect(
    () => () => {
      operationGeneration.current += 1;
    },
    [],
  );

  async function handleAdd(normalizedName: string, versionSpec?: string) {
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingOperation("add");
    const result = await addRegistryArtifact(
      versionSpec ? { normalizedName, versionSpec } : { normalizedName },
    );
    if (generation !== operationGeneration.current) return;

    setPendingOperation(null);
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
    setPendingOperation("credential");
    const result = await submitRegistryCredential(key);
    if (generation !== operationGeneration.current) return;

    if (result.status === "connected") {
      const collections = await refreshRegistryCollections();
      if (generation !== operationGeneration.current) return;
      setPendingOperation(null);
      if (collections.status === "complete") {
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
    if (result.status === "pending" || result.status === "invalid") {
      setAccessDialogMode(undefined);
      setState((current) =>
        current.status === REGISTRY_BOOTSTRAP_STATE.ONBOARDING ||
        current.status === REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
          ? {
              status:
                result.status === "pending"
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
      result.status === "replacement_failed"
        ? "Registry key validation failed. Existing access is unchanged."
        : "Registry key validation could not be completed. Try again.",
    );
  }

  async function handleDisconnect() {
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingOperation("credential");
    const result = await disconnectRegistryCredential();
    if (generation !== operationGeneration.current) return;

    setPendingOperation(null);
    if (result.status !== "disconnected") {
      setOperationMessage(
        "Registry access could not be disconnected. Try again.",
      );
      return;
    }

    setAccessDialogMode(undefined);
    setSelectedName(undefined);
    setState({
      status: REGISTRY_BOOTSTRAP_STATE.ONBOARDING,
      credential: result.credential,
      tenantArtifacts: result.tenantArtifacts,
    });
  }

  async function handleRemove(normalizedName: string) {
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingOperation("remove");
    const result = await removeRegistryArtifact(normalizedName);
    if (generation !== operationGeneration.current) return;

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

  function openArtifactPanel(
    normalizedName: string,
    trigger: HTMLElement | null,
  ) {
    panelTriggerRef.current = trigger;
    setSelectedName(normalizedName);
  }

  const accessDialogProps = {
    onOpenChange: (open: boolean) => {
      if (!open && pendingOperation !== "credential") {
        setAccessDialogMode(undefined);
      }
    },
    onSubmit: handleCredentialSubmit,
    open: true,
    pending: pendingOperation === "credential",
    returnFocusRef:
      accessDialogMode === "connect" ? connectButtonRef : manageButtonRef,
  };
  const accessDialog =
    accessDialogMode === "connect" ? (
      <RegistryAccessDialog mode="connect" {...accessDialogProps} />
    ) : accessDialogMode === "manage" ? (
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
        {operationMessage && <p role="alert">{operationMessage}</p>}
        <RegistryCredentialBanner
          connectButtonRef={connectButtonRef}
          onConnect={() => setAccessDialogMode("connect")}
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
      incomplete: [
        "Registry catalog is incomplete",
        "Complete catalog controls and metrics are unavailable until every catalog page loads. Retry to load the catalog again.",
      ],
      unavailable: [
        "Registry is unavailable",
        "Registry data may be stale or unavailable. Retry when the service is available.",
      ],
      reconnect: [
        "Reconnect Registry",
        "Reconnect Registry before exploring artifacts.",
      ],
      error: [
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

  const selectedDetail = selectedName
    ? getRegistryArtifactDetail(
        selectedName,
        state.catalog.artifacts,
        state.tenantArtifacts,
      )
    : null;
  const isPanelOpen = selectedDetail !== null;

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
            onClick={() => setAccessDialogMode("manage")}
            ref={manageButtonRef}
            type="button"
            variant="outline"
          >
            Manage access
          </Button>
        </div>
      </div>
      {!isPanelOpen && operationMessage && (
        <p role="alert">{operationMessage}</p>
      )}
      <Tabs
        onValueChange={(value) => setActiveTab(value as "explore" | "mine")}
        value={activeTab}
      >
        <TabsList className="border-b">
          <TabsTrigger
            adornment={
              <Badge size="sm" variant="tag">
                {state.catalog.artifacts.length}
              </Badge>
            }
            value="explore"
          >
            Explore
          </TabsTrigger>
          <TabsTrigger
            adornment={
              <Badge size="sm" variant="tag">
                {state.tenantArtifacts.length}
              </Badge>
            }
            value="mine"
          >
            My artifacts
          </TabsTrigger>
        </TabsList>
        <TabsContent className="space-y-4 pt-4" value="explore">
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
                  onOpen={(trigger) =>
                    openArtifactPanel(artifact.normalizedName, trigger)
                  }
                />
              </li>
            ))}
          </RegistryArtifactGrid>
        </TabsContent>
        <TabsContent className="space-y-4 pt-4" value="mine">
          <RegistryArtifactGrid
            emptyMessage="No artifacts in this workspace yet."
            isEmpty={model.myArtifacts.length === 0}
          >
            {model.myArtifacts.map((myArtifact) => (
              <li key={myArtifact.normalizedName}>
                {myArtifact.catalogArtifact ? (
                  <RegistryArtifactCard
                    artifact={myArtifact.catalogArtifact}
                    onOpen={(trigger) =>
                      openArtifactPanel(myArtifact.normalizedName, trigger)
                    }
                  />
                ) : (
                  <RegistryTenantArtifactCard
                    normalizedName={myArtifact.normalizedName}
                    onOpen={(trigger) =>
                      openArtifactPanel(myArtifact.normalizedName, trigger)
                    }
                    versionSpec={myArtifact.versionSpec}
                  />
                )}
              </li>
            ))}
          </RegistryArtifactGrid>
        </TabsContent>
      </Tabs>
      <RegistryArtifactPanel
        onClose={() => setSelectedName(undefined)}
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          panelTriggerRef.current?.focus();
        }}
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          detailHeadingRef.current?.focus();
        }}
        open={isPanelOpen}
      >
        {selectedDetail && (
          <RegistryArtifactDetail
            key={selectedName}
            {...selectedDetail}
            headingRef={detailHeadingRef}
            isMutationPending={pendingOperation === "add"}
            operationMessage={operationMessage}
            removeButtonRef={removeButtonRef}
            onAdd={
              selectedDetail.catalogArtifact && !selectedDetail.tenantArtifact
                ? (versionSpec) =>
                    handleAdd(
                      selectedDetail.catalogArtifact!.normalizedName,
                      versionSpec,
                    )
                : undefined
            }
            onRemove={
              selectedDetail.tenantArtifact
                ? () =>
                    setRemoveTarget(
                      selectedDetail.tenantArtifact!.normalizedName,
                    )
                : undefined
            }
          />
        )}
      </RegistryArtifactPanel>
      {accessDialog}
      <RegistryRemoveDialog
        artifactName={removeTarget}
        isPending={pendingOperation === "remove"}
        onConfirm={() => removeTarget && handleRemove(removeTarget)}
        onOpenChange={(open) => {
          if (!open && pendingOperation !== "remove")
            setRemoveTarget(undefined);
        }}
        open={removeTarget !== undefined}
        returnFocusRef={removeButtonRef}
      />
    </div>
  );
}
