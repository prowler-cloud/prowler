"use client";

import { Settings } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useEffectEvent, useRef, useState } from "react";

import {
  disconnectRegistryCredential,
  removeRegistryArtifact,
} from "@/actions/registry/registry";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn/tabs/tabs";
import { toast } from "@/components/shadcn/toast/use-toast";
import { executeRegistryArtifactAddition } from "@/lib/registry/artifact-execution";
import { isRegistryArtifactInstallable } from "@/lib/registry/artifacts";
import { executeRegistryCredentialValidation } from "@/lib/registry/credential-execution";
import {
  REGISTRY_CREDENTIAL_CHANGED,
  credentialOutcomeMessage,
  type RegistryCredentialValidationOutcome,
} from "@/lib/registry/credential-result";
import { useTaskWatcherStore } from "@/store/task-watcher/store";
import {
  REGISTRY_BOOTSTRAP_STATE,
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
import {
  buildRegistryMarketplaceModel,
  REGISTRY_MARKETPLACE_SORT,
  REGISTRY_CATALOG_CAPABILITY,
  type RegistryCatalogCapability,
  type RegistryExplorerFilters,
  type RegistryMarketplaceArtifact,
  type RegistryMarketplaceSort,
} from "./registry-explorer.model";
import { RegistryRemoveDialog } from "./registry-remove-dialog";
import { RegistryToolbar } from "./registry-toolbar";

const PAGE_SUBTITLE =
  "Explore checks, compliance frameworks, and providers. Add external provider artifacts to connect new providers to your workspace.";

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
  registryKeyUrl?: string;
}

export function RegistryExplorer({
  initialState,
  registryKeyUrl,
}: RegistryExplorerProps) {
  // The API is the sole access authority: a denied action result routes to
  // Profile once, and the navigation unmounts this component with its state.
  const router = useRouter();
  const [state, setState] = useState(initialState);
  const searchParams = useSearchParams();
  const filters: RegistryExplorerFilters = {
    search: searchParams.get("filter[search]") ?? undefined,
    providers:
      searchParams.get("filter[provider]")?.split(",").filter(Boolean) ?? [],
    capabilities: (
      searchParams.get("filter[capability]")?.split(",") ?? []
    ).filter((value): value is RegistryCatalogCapability =>
      Object.values(REGISTRY_CATALOG_CAPABILITY).includes(
        value as RegistryCatalogCapability,
      ),
    ),
  };
  const sort =
    searchParams.get("sort") === REGISTRY_MARKETPLACE_SORT.DOWNLOADS
      ? REGISTRY_MARKETPLACE_SORT.DOWNLOADS
      : REGISTRY_MARKETPLACE_SORT.NAME;
  const activeTab =
    searchParams.get("tab") === REGISTRY_TAB.MINE
      ? REGISTRY_TAB.MINE
      : REGISTRY_TAB.EXPLORE;
  function updateView(values: Record<string, string | undefined>) {
    const next = new URLSearchParams(searchParams.toString());
    Object.entries(values).forEach(([key, value]) =>
      value ? next.set(key, value) : next.delete(key),
    );
    window.history.replaceState(
      null,
      "",
      `/registry${next.size ? `?${next}` : ""}`,
    );
  }
  const setFilters = (next: RegistryExplorerFilters) =>
    updateView({
      "filter[search]": next.search,
      "filter[provider]": next.providers?.join(","),
      "filter[capability]": next.capabilities?.join(","),
    });
  const setSort = (next: RegistryMarketplaceSort) =>
    updateView({
      sort: next === REGISTRY_MARKETPLACE_SORT.NAME ? undefined : next,
    });
  const setActiveTab = (next: RegistryTab) =>
    updateView({ tab: next === REGISTRY_TAB.EXPLORE ? undefined : next });
  const [pendingOperation, setPendingOperation] =
    useState<RegistryPendingOperation | null>(null);
  const [localPendingAddName, setPendingAddName] = useState<string>();
  const watchedTasks = useTaskWatcherStore((store) => store.tasks);
  const pendingAddName =
    localPendingAddName ||
    Object.values(watchedTasks).find(
      (task) =>
        task.kind === "registry-artifact-add" && task.status === "pending",
    )?.meta.normalizedName;
  useEffect(() => {
    const refresh = (event: Event) => {
      if (!(event instanceof CustomEvent) || !Array.isArray(event.detail))
        return;
      setState((current) =>
        current.status === "ready"
          ? { ...current, tenantArtifacts: event.detail }
          : current,
      );
    };
    window.addEventListener("registry-artifacts-changed", refresh);
    return () =>
      window.removeEventListener("registry-artifacts-changed", refresh);
  }, [router]);
  const [accessDialogMode, setAccessDialogMode] =
    useState<RegistryAccessDialogMode>();
  const [removeTarget, setRemoveTarget] = useState<string>();
  const [operationMessage, setOperationMessage] = useState<string>();
  const connectButtonRef = useRef<HTMLButtonElement>(null);
  const manageButtonRef = useRef<HTMLButtonElement>(null);
  const removeTriggerRef = useRef<HTMLButtonElement | null>(null);
  const operationGeneration = useRef(0);
  const awaitingCredential = useRef(false);

  useEffect(
    () => () => {
      operationGeneration.current += 1;
    },
    [],
  );

  const consumeCredentialOutcome = useEffectEvent(
    (result: RegistryCredentialValidationOutcome) => {
      if (!awaitingCredential.current) applyCredentialOutcome(result);
    },
  );
  useEffect(() => {
    const consume = (event: Event) => {
      if (event instanceof CustomEvent) consumeCredentialOutcome(event.detail);
    };
    window.addEventListener(REGISTRY_CREDENTIAL_CHANGED, consume);
    return () =>
      window.removeEventListener(REGISTRY_CREDENTIAL_CHANGED, consume);
  }, []);

  function applyCredentialOutcome(result: RegistryCredentialValidationOutcome) {
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED) {
      router.replace("/profile");
      return;
    }
    setPendingOperation(null);
    if (result.status === REGISTRY_CREDENTIAL_ACTION.CONNECTED) {
      setAccessDialogMode(undefined);
      setOperationMessage(undefined);
      setState({
        status: REGISTRY_BOOTSTRAP_STATE.READY,
        credential: result.credential,
        catalog: result.collections.catalog,
        tenantArtifacts: result.collections.tenantArtifacts,
      });
      return;
    }
    if (
      result.status === REGISTRY_CREDENTIAL_ACTION.PENDING ||
      result.status === REGISTRY_CREDENTIAL_ACTION.INVALID
    ) {
      setState((current) =>
        current.status === REGISTRY_BOOTSTRAP_STATE.ONBOARDING ||
        current.status === REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
          ? {
              status:
                result.status === REGISTRY_CREDENTIAL_ACTION.PENDING
                  ? REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
                  : REGISTRY_BOOTSTRAP_STATE.ONBOARDING,
              credential: result.credential ?? current.credential,
              tenantArtifacts: current.tenantArtifacts,
            }
          : current,
      );
    }
    setOperationMessage(credentialOutcomeMessage(result));
  }

  async function handleAdd(artifact: RegistryMarketplaceArtifact) {
    if (
      !isRegistryArtifactInstallable(artifact) ||
      artifact.isAdded ||
      pendingAddName
    )
      return;
    const { normalizedName } = artifact;
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingAddName(normalizedName);
    const result = await executeRegistryArtifactAddition({ normalizedName });
    if (generation !== operationGeneration.current) return;
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED)
      return router.replace("/profile");

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
  }

  async function handleCredentialSubmit(key: string) {
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingOperation(REGISTRY_PENDING_OPERATION.CREDENTIAL);
    awaitingCredential.current = true;
    const result = await executeRegistryCredentialValidation(key);
    awaitingCredential.current = false;
    if (generation !== operationGeneration.current) return;
    applyCredentialOutcome(result);
  }

  async function handleDisconnect() {
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingOperation(REGISTRY_PENDING_OPERATION.CREDENTIAL);
    const result = await disconnectRegistryCredential();
    if (generation !== operationGeneration.current) return;
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED)
      return router.replace("/profile");

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
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED)
      return router.replace("/profile");

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
    window.dispatchEvent(
      new CustomEvent("registry-artifacts-changed", {
        detail: result.tenantArtifacts,
      }),
    );
  }

  function openRemoveDialog(
    normalizedName: string,
    trigger: HTMLButtonElement | null,
  ) {
    removeTriggerRef.current = trigger;
    setRemoveTarget(normalizedName);
  }

  const accessDialogProps = {
    registryKeyUrl,
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
          <Alert variant="error">
            <AlertDescription>{operationMessage}</AlertDescription>
          </Alert>
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
    return (
      <>
        <RetryState title={title}>{message}</RetryState>
        {state.status === REGISTRY_BOOTSTRAP_STATE.RECONNECT && (
          <div className="flex justify-center">
            <Button
              onClick={() =>
                setAccessDialogMode(REGISTRY_ACCESS_DIALOG_MODE.MANAGE)
              }
              ref={manageButtonRef}
              type="button"
            >
              Replace key
            </Button>
          </div>
        )}
        {accessDialog}
      </>
    );
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
      <p className="text-text-neutral-secondary text-sm">{PAGE_SUBTITLE}</p>
      {!accessDialogMode && operationMessage && (
        <Alert variant="error">
          <AlertDescription>{operationMessage}</AlertDescription>
        </Alert>
      )}
      <Tabs
        onValueChange={(value) => setActiveTab(value as RegistryTab)}
        value={activeTab}
      >
        <div className="border-border-neutral-secondary flex items-center justify-between gap-4 border-b">
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
          <Button
            aria-label="Manage access"
            title="Manage access"
            onClick={() =>
              setAccessDialogMode(REGISTRY_ACCESS_DIALOG_MODE.MANAGE)
            }
            ref={manageButtonRef}
            size="icon"
            type="button"
            variant="ghost"
          >
            <Settings aria-hidden />
          </Button>
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
            emptyDescription={
              state.catalog.artifacts.length === 0
                ? "Published artifacts will appear here when the Registry catalog is available."
                : undefined
            }
            emptyActionLabel={
              state.catalog.artifacts.length === 0
                ? "Refresh catalog"
                : undefined
            }
            onReset={
              state.catalog.artifacts.length > 0
                ? () => setFilters({})
                : () => window.location.reload()
            }
            isEmpty={model.artifacts.length === 0}
          >
            {model.artifacts.map((artifact) => (
              <li key={artifact.normalizedName}>
                <RegistryArtifactCard
                  artifact={artifact}
                  pendingAddName={pendingAddName}
                  onAdd={() => handleAdd(artifact)}
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
            emptyDescription="Explore the catalog to add an external provider to this workspace."
            emptyActionLabel="Explore artifacts"
            isEmpty={model.myArtifacts.length === 0}
            onReset={() => setActiveTab(REGISTRY_TAB.EXPLORE)}
          >
            {model.myArtifacts.map((myArtifact) => (
              <li key={myArtifact.normalizedName}>
                {myArtifact.catalogArtifact ? (
                  <RegistryArtifactCard
                    artifact={myArtifact.catalogArtifact}
                    pendingAddName={pendingAddName}
                    onAdd={() => handleAdd(myArtifact.catalogArtifact!)}
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
