"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import {
  addRegistryArtifact,
  disconnectRegistryCredential,
  refreshRegistryCollections,
  removeRegistryArtifact,
  submitRegistryCredential,
} from "@/actions/registry/registry";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import {
  Sheet,
  SheetContent,
  SheetTitle,
  SheetTrigger,
} from "@/components/shadcn/sheet";
import { toast } from "@/components/shadcn/toast/use-toast";
import {
  REGISTRY_BOOTSTRAP_STATE,
  REGISTRY_MUTATION,
  type RegistryBootstrapState,
  type RegistryMutationResult,
} from "@/types/registry";

import { RegistryAccessDialog } from "./registry-access-dialog";
import { RegistryArtifactDetail } from "./registry-artifact-detail";
import {
  buildRegistryExplorerModel,
  getRegistryArtifactDetail,
  type RegistryExplorerFilters,
} from "./registry-explorer.model";
import { RegistryNavigation } from "./registry-navigation";
import { RegistryOnboarding } from "./registry-onboarding";
import { RegistryOverview } from "./registry-overview";
import { RegistryRemoveDialog } from "./registry-remove-dialog";

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

function artifactName(id: string) {
  return id.startsWith("leaf:")
    ? decodeURIComponent(id.slice(id.lastIndexOf(":") + 1))
    : undefined;
}

function mutationFailureMessage(result: RegistryMutationResult) {
  if (result.status === REGISTRY_MUTATION.REFUSED) return result.message;
  if (result.status === REGISTRY_MUTATION.REFRESH_FAILED) {
    return "Registry membership could not be confirmed. Try again.";
  }
  return "The Registry operation could not be completed. Try again.";
}

export function RegistryExplorer({
  initialState,
}: {
  initialState: RegistryBootstrapState;
}) {
  // The API is the sole access authority: a denied action result routes to
  // Profile once, and the navigation unmounts this component with its state.
  const router = useRouter();
  const [state, setState] = useState(initialState);
  const [filters, setFilters] = useState<RegistryExplorerFilters>({});
  const [selectedId, setSelectedId] = useState("root:available");
  const [expandedIds, setExpandedIds] = useState([
    "root:available",
    "root:my-artifacts",
  ]);
  const [pendingOperation, setPendingOperation] = useState<
    "add" | "credential" | "remove" | null
  >(null);
  const [accessDialogMode, setAccessDialogMode] = useState<
    "connect" | "manage"
  >();
  const [removeTarget, setRemoveTarget] = useState<string>();
  const [operationMessage, setOperationMessage] = useState<string>();
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);
  const detailHeadingRef = useRef<HTMLHeadingElement>(null);
  const connectButtonRef = useRef<HTMLButtonElement>(null);
  const manageButtonRef = useRef<HTMLButtonElement>(null);
  const removeButtonRef = useRef<HTMLButtonElement>(null);
  const focusDetailAfterMobileClose = useRef(false);
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
    if (result.status === "access_denied") return router.replace("/profile");

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
    if (result.status === "access_denied") return router.replace("/profile");

    if (result.status === "connected") {
      const collections = await refreshRegistryCollections();
      if (generation !== operationGeneration.current) return;
      if (collections.status === "access_denied")
        return router.replace("/profile");
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
    if (result.status === "access_denied") return router.replace("/profile");

    setPendingOperation(null);
    if (result.status !== "disconnected") {
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
    setPendingOperation("remove");
    const result = await removeRegistryArtifact(normalizedName);
    if (generation !== operationGeneration.current) return;
    if (result.status === "access_denied") return router.replace("/profile");

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

  function handleSelectedIdChange(id: string) {
    setSelectedId(id);
    if (mobileNavigationOpen && artifactName(id)) {
      focusDetailAfterMobileClose.current = true;
      setMobileNavigationOpen(false);
    }
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
      <>
        <RegistryOnboarding
          connectButtonRef={connectButtonRef}
          onConnect={() => setAccessDialogMode("connect")}
          tenantArtifacts={state.tenantArtifacts}
          validationPending={
            state.status === REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
          }
        />
        {accessDialog}
      </>
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

  const model = buildRegistryExplorerModel(
    state.catalog,
    state.tenantArtifacts,
    filters,
  );
  if (!model.isComplete) {
    return (
      <RetryState title="Registry catalog is incomplete">
        Complete catalog controls and metrics are unavailable.
      </RetryState>
    );
  }
  if (state.catalog.artifacts.length === 0) {
    return (
      <>
        <Card aria-label="Available artifacts" role="region" variant="base">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1 className="text-xl font-semibold">Available artifacts</h1>
              <p className="text-text-neutral-secondary mt-2 text-sm">
                No Registry artifacts are available.
              </p>
            </div>
            <Button
              onClick={() => setAccessDialogMode("manage")}
              ref={manageButtonRef}
              variant="outline"
            >
              Manage access
            </Button>
          </div>
          {operationMessage && <p role="alert">{operationMessage}</p>}
          {state.tenantArtifacts.length > 0 && (
            <section aria-label="My artifacts" className="mt-6">
              <h2 className="text-base font-semibold">My artifacts</h2>
              <ul className="mt-3 space-y-2 text-sm">
                {state.tenantArtifacts.map((artifact) => (
                  <li
                    className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1"
                    key={artifact.normalizedName}
                  >
                    <span>{artifact.normalizedName}</span>
                    <span className="text-text-neutral-secondary">
                      {artifact.versionSpec}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </Card>
        {accessDialog}
      </>
    );
  }
  const selectedDetail = artifactName(selectedId)
    ? getRegistryArtifactDetail(
        artifactName(selectedId)!,
        state.catalog.artifacts,
        state.tenantArtifacts,
      )
    : null;
  const providers = model.hierarchy.providers.map(({ provider }) => provider);
  const navigation = (
    <RegistryNavigation
      artifacts={model.available}
      expandedIds={expandedIds}
      filters={filters}
      onExpandedChange={setExpandedIds}
      onFiltersChange={setFilters}
      onSelectedIdChange={handleSelectedIdChange}
      providers={providers}
      selectedId={selectedId}
      tenantArtifacts={state.tenantArtifacts}
    />
  );

  return (
    <div className="grid gap-6 lg:grid-cols-[18rem_minmax(0,1fr)]">
      <aside className="hidden lg:block">{navigation}</aside>
      <div className="lg:hidden">
        <Sheet
          onOpenChange={setMobileNavigationOpen}
          open={mobileNavigationOpen}
        >
          <SheetTrigger asChild>
            <Button variant="outline">Browse artifacts</Button>
          </SheetTrigger>
          <SheetContent
            onCloseAutoFocus={(event) => {
              if (focusDetailAfterMobileClose.current) {
                event.preventDefault();
                detailHeadingRef.current?.focus();
                focusDetailAfterMobileClose.current = false;
              }
            }}
            side="left"
          >
            <SheetTitle>Browse artifacts</SheetTitle>
            {navigation}
          </SheetContent>
        </Sheet>
      </div>
      <main>
        <Button
          onClick={() => setAccessDialogMode("manage")}
          ref={manageButtonRef}
          type="button"
          variant="outline"
        >
          Manage access
        </Button>
        {operationMessage && <p role="alert">{operationMessage}</p>}
        {selectedDetail ? (
          <RegistryArtifactDetail
            {...selectedDetail}
            headingRef={detailHeadingRef}
            isMutationPending={pendingOperation === "add"}
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
        ) : (
          <RegistryOverview
            availableArtifacts={model.available}
            metrics={model.metrics}
            selectedId={selectedId}
            tenantArtifacts={state.tenantArtifacts}
          />
        )}
      </main>
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
