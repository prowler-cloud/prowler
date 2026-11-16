"use client";

import {
  KeyRound,
  PackageSearch,
  RefreshCw,
  SearchX,
  TriangleAlert,
} from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  type ReactNode,
  type Ref,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
} from "react";

import {
  disconnectRegistryCredential,
  removeRegistryArtifact,
} from "@/actions/registry/registry";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  StatusPanel,
  StatusPanelActions,
  StatusPanelBody,
  StatusPanelDescription,
  StatusPanelIcon,
  StatusPanelTitle,
} from "@/components/shadcn/status-panel";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn/tabs/tabs";
import { toast } from "@/components/shadcn/toast/use-toast";
import { executeRegistryArtifactAddition } from "@/lib/registry/artifact-execution";
import { executeRegistryCredentialValidation } from "@/lib/registry/credential-execution";
import {
  REGISTRY_CREDENTIAL_CHANGED,
  credentialOutcomeMessage,
  type RegistryCredentialValidationOutcome,
} from "@/lib/registry/credential-result";
import { useTaskWatcherStore } from "@/store/task-watcher/store";
import {
  REGISTRY_ARTIFACT_REMOVAL,
  REGISTRY_BOOTSTRAP_STATE,
  REGISTRY_CREDENTIAL_ACTION,
  REGISTRY_FAILURE,
  REGISTRY_INSTALL_OPERATION,
  REGISTRY_MUTATION,
  type RegistryArtifactRemovalResult,
  type RegistryBootstrapState,
  type RegistryMutationResult,
  type RegistryRemoveDialogError,
  type RegistryTenantArtifact,
} from "@/types/registry";

import {
  REGISTRY_KEY_STATUS,
  RegistryAccessDialog,
} from "./registry-access-dialog";
import {
  RegistryArtifactCard,
  RegistryTenantArtifactCard,
} from "./registry-artifact-card";
import { RegistryArtifactGrid } from "./registry-artifact-grid";
import {
  REGISTRY_CREDENTIAL_BANNER,
  RegistryCredentialBanner,
} from "./registry-credential-banner";
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
import { useRegistryRefresh } from "./use-registry-refresh";

const PAGE_SUBTITLE =
  "Explore checks, compliance frameworks, and providers. Add artifacts to connect new providers or to run more checks on the ones you already scan.";

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

type RegistryStatusKind =
  | typeof REGISTRY_BOOTSTRAP_STATE.INCOMPLETE
  | typeof REGISTRY_BOOTSTRAP_STATE.UNAVAILABLE
  | typeof REGISTRY_BOOTSTRAP_STATE.RECONNECT
  | typeof REGISTRY_BOOTSTRAP_STATE.ERROR;

const REGISTRY_STATUS_COPY = {
  [REGISTRY_BOOTSTRAP_STATE.INCOMPLETE]: {
    title: "Registry catalog is incomplete",
    description:
      "Complete catalog controls and metrics are unavailable until every catalog page loads. Retry to load the catalog again.",
  },
  [REGISTRY_BOOTSTRAP_STATE.UNAVAILABLE]: {
    title: "Registry is unavailable",
    description:
      "Registry data may be stale or unavailable. Retry when the service is available.",
  },
  [REGISTRY_BOOTSTRAP_STATE.RECONNECT]: {
    title: "Reconnect the Registry",
    description:
      "The Registry rejected the connected API key. Replace it to load the catalog again.",
  },
  [REGISTRY_BOOTSTRAP_STATE.ERROR]: {
    title: "Registry could not be loaded",
    description:
      "An unexpected Registry error occurred. Retry to load the explorer again.",
  },
} as const satisfies Record<
  RegistryStatusKind,
  { title: string; description: string }
>;

interface RegistryStatusStateProps {
  status: RegistryStatusKind;
  onReplaceKey: () => void;
  replaceKeyButtonRef: Ref<HTMLButtonElement>;
}

function RegistryStatusState({
  status,
  onReplaceKey,
  replaceKeyButtonRef,
}: RegistryStatusStateProps) {
  const { title, description } = REGISTRY_STATUS_COPY[status];
  const isReconnect = status === REGISTRY_BOOTSTRAP_STATE.RECONNECT;

  return (
    <StatusPanel aria-live="polite">
      <StatusPanelIcon>
        {isReconnect ? (
          <TriangleAlert className="text-text-warning-primary" />
        ) : (
          <RefreshCw />
        )}
      </StatusPanelIcon>
      <StatusPanelBody>
        <StatusPanelTitle>{title}</StatusPanelTitle>
        <StatusPanelDescription>{description}</StatusPanelDescription>
      </StatusPanelBody>
      <StatusPanelActions>
        {isReconnect && (
          <Button
            onClick={onReplaceKey}
            ref={replaceKeyButtonRef}
            type="button"
          >
            Replace key
          </Button>
        )}
        <Button
          onClick={() => window.location.reload()}
          type="button"
          variant={isReconnect ? "outline" : "default"}
        >
          Retry
        </Button>
      </StatusPanelActions>
    </StatusPanel>
  );
}

interface RegistryEmptyStateProps {
  icon: ReactNode;
  title: string;
  description: string;
  actionLabel: string;
  onAction: () => void;
}

function RegistryEmptyState({
  icon,
  title,
  description,
  actionLabel,
  onAction,
}: RegistryEmptyStateProps) {
  return (
    <StatusPanel>
      <StatusPanelIcon>{icon}</StatusPanelIcon>
      <StatusPanelBody>
        <StatusPanelTitle>{title}</StatusPanelTitle>
        <StatusPanelDescription>{description}</StatusPanelDescription>
      </StatusPanelBody>
      <StatusPanelActions>
        <Button onClick={onAction} type="button" variant="outline">
          {actionLabel}
        </Button>
      </StatusPanelActions>
    </StatusPanel>
  );
}

// Shared by the onboarding and ready views.
function RegistryPageIntro({ errorMessage }: { errorMessage?: string }) {
  return (
    <>
      <p className="text-text-neutral-secondary text-sm">{PAGE_SUBTITLE}</p>
      {errorMessage && (
        <Alert variant="error">
          <AlertDescription>{errorMessage}</AlertDescription>
        </Alert>
      )}
    </>
  );
}

interface RegistryRemoveTarget {
  normalizedName: string;
  /** Display name shown in the dialog. */
  label: string;
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
  registryUrl?: string;
}

export function RegistryExplorer({
  initialState,
  registryUrl,
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
  const setActiveTab = (next: RegistryTab) => {
    updateView({ tab: next === REGISTRY_TAB.EXPLORE ? undefined : next });
    if (next !== activeTab) requestRefresh();
  };
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
  const [refreshMessage, setRefreshMessage] = useState<string>();
  const { isRefreshing, requestRefresh, invalidateRefresh } =
    useRegistryRefresh({
      enabled: state.status === REGISTRY_BOOTSTRAP_STATE.READY,
      mutationPending: Boolean(pendingOperation || pendingAddName),
      onResult: (result) => {
        if (result.status === "access_denied") {
          router.replace("/profile");
        } else if (result.status === "subscription_required") {
          // The server page swaps the catalog for the paid-plan prompt.
          router.refresh();
        } else if (result.status === "complete") {
          setRefreshMessage(undefined);
          setState((current) =>
            current.status === "ready"
              ? {
                  ...current,
                  catalog: result.catalog,
                  tenantArtifacts: result.tenantArtifacts,
                }
              : current,
          );
        } else if (result.status === "reconnect") {
          setState({ status: REGISTRY_BOOTSTRAP_STATE.RECONNECT });
        } else if (result.status === "onboarding") {
          setState((current) =>
            current.status === "ready"
              ? {
                  status: REGISTRY_BOOTSTRAP_STATE.ONBOARDING,
                  credential: {
                    configured: false,
                    isValid: false,
                    scopes: [],
                    validationPending: false,
                  },
                  tenantArtifacts: current.tenantArtifacts,
                }
              : current,
          );
        } else {
          setRefreshMessage(
            "Registry could not be refreshed. Showing the last available data. Try again.",
          );
        }
      },
    });
  const consumeArtifactsChanged = useEffectEvent(
    (artifacts: RegistryTenantArtifact[]) => {
      invalidateRefresh();
      setState((current) =>
        current.status === "ready"
          ? { ...current, tenantArtifacts: artifacts }
          : current,
      );
    },
  );
  useEffect(() => {
    const refresh = (event: Event) => {
      if (!(event instanceof CustomEvent) || !Array.isArray(event.detail))
        return;
      consumeArtifactsChanged(event.detail);
    };
    window.addEventListener("registry-artifacts-changed", refresh);
    return () =>
      window.removeEventListener("registry-artifacts-changed", refresh);
  }, []);
  const [accessDialogMode, setAccessDialogMode] =
    useState<RegistryAccessDialogMode>();
  const [removeTarget, setRemoveTarget] = useState<RegistryRemoveTarget>();
  const [removeError, setRemoveError] = useState<RegistryRemoveDialogError>();
  const [operationMessage, setOperationMessage] = useState<string>();
  const connectButtonRef = useRef<HTMLButtonElement>(null);
  const manageButtonRef = useRef<HTMLButtonElement>(null);
  const removeTriggerRef = useRef<HTMLButtonElement | null>(null);
  const operationGeneration = useRef(0);
  const artifactSubmission = useRef(false);
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
    // A connected outcome already includes fresh collections. A failed
    // replacement must still resume any read deferred during that mutation.
    invalidateRefresh(
      result.status === REGISTRY_CREDENTIAL_ACTION.CONNECTED
        ? false
        : undefined,
    );
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED) {
      router.replace("/profile");
      return;
    }
    setPendingOperation(null);
    if (result.status === REGISTRY_CREDENTIAL_ACTION.CONNECTED) {
      setRefreshMessage(undefined);
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
      !artifact.isInstallable ||
      (artifact.isAdded && !artifact.updateAvailable) ||
      pendingAddName ||
      pendingOperation ||
      artifactSubmission.current
    )
      return;
    const { normalizedName } = artifact;
    invalidateRefresh();
    artifactSubmission.current = true;
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingAddName(normalizedName);
    const result = await executeRegistryArtifactAddition(
      artifact.updateAvailable && artifact.latestVersion
        ? {
            normalizedName,
            versionSpec: artifact.latestVersion,
            operation: REGISTRY_INSTALL_OPERATION.UPDATE,
          }
        : { normalizedName },
    );
    artifactSubmission.current = false;
    if (generation !== operationGeneration.current) return;
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED)
      return router.replace("/profile");

    setPendingAddName(undefined);
    if (result.status !== REGISTRY_MUTATION.CONFIRMED) {
      setOperationMessage(
        artifact.updateAvailable &&
          result.status === REGISTRY_MUTATION.REFRESH_FAILED
          ? "Update could not be confirmed. Refresh Registry before retrying."
          : mutationFailureMessage(result),
      );
      return;
    }

    setState((current) =>
      current.status === REGISTRY_BOOTSTRAP_STATE.READY
        ? { ...current, tenantArtifacts: result.tenantArtifacts }
        : current,
    );
  }

  async function handleCredentialSubmit(key: string) {
    invalidateRefresh();
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
    invalidateRefresh();
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setPendingOperation(REGISTRY_PENDING_OPERATION.CREDENTIAL);
    const result = await disconnectRegistryCredential().catch(() => ({
      status: REGISTRY_FAILURE.ERROR,
    }));
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
    if (
      pendingOperation === REGISTRY_PENDING_OPERATION.REMOVE ||
      pendingAddName === normalizedName
    )
      return;
    invalidateRefresh();
    const generation = operationGeneration.current;
    setOperationMessage(undefined);
    setRemoveError(undefined);
    setPendingOperation(REGISTRY_PENDING_OPERATION.REMOVE);
    let result: RegistryArtifactRemovalResult;
    try {
      result = await removeRegistryArtifact(normalizedName);
    } catch {
      result = { status: REGISTRY_FAILURE.ERROR };
    }
    if (generation !== operationGeneration.current) return;
    setPendingOperation(null);
    if (result.status === REGISTRY_FAILURE.ACCESS_DENIED)
      return router.replace("/profile");

    if (
      result.status === REGISTRY_ARTIFACT_REMOVAL.IN_USE ||
      result.status === REGISTRY_ARTIFACT_REMOVAL.BUSY
    ) {
      setRemoveError(result);
      return;
    }
    if (result.status !== REGISTRY_MUTATION.CONFIRMED) {
      setRemoveError({
        status: REGISTRY_FAILURE.ERROR,
        message: mutationFailureMessage(result),
      });
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
    target: RegistryRemoveTarget,
    trigger: HTMLButtonElement | null,
  ) {
    removeTriggerRef.current = trigger;
    setRemoveError(undefined);
    setRemoveTarget(target);
  }
  const catalogRemoveTarget = (artifact: RegistryMarketplaceArtifact) => ({
    normalizedName: artifact.normalizedName,
    label: artifact.name ?? artifact.normalizedName,
  });

  const accessDialogProps = {
    registryUrl,
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
        keyStatus={
          state.status === REGISTRY_BOOTSTRAP_STATE.READY
            ? REGISTRY_KEY_STATUS.CONNECTED
            : state.status === REGISTRY_BOOTSTRAP_STATE.RECONNECT
              ? REGISTRY_KEY_STATUS.REJECTED
              : undefined
        }
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
        <RegistryPageIntro
          errorMessage={accessDialogMode ? undefined : operationMessage}
        />
        <RegistryCredentialBanner
          variant={
            state.status === REGISTRY_BOOTSTRAP_STATE.VALIDATION_PENDING
              ? REGISTRY_CREDENTIAL_BANNER.VALIDATING
              : REGISTRY_CREDENTIAL_BANNER.ONBOARDING
          }
          connectButtonRef={connectButtonRef}
          registryUrl={registryUrl}
          onConnect={() =>
            setAccessDialogMode(REGISTRY_ACCESS_DIALOG_MODE.CONNECT)
          }
          tenantArtifactCount={state.tenantArtifacts.length}
        />
        {accessDialog}
      </div>
    );
  }
  const openManageDialog = () =>
    setAccessDialogMode(REGISTRY_ACCESS_DIALOG_MODE.MANAGE);
  if (state.status !== REGISTRY_BOOTSTRAP_STATE.READY) {
    return (
      <>
        <RegistryStatusState
          status={state.status}
          onReplaceKey={openManageDialog}
          replaceKeyButtonRef={manageButtonRef}
        />
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
      <RegistryStatusState
        status={REGISTRY_BOOTSTRAP_STATE.INCOMPLETE}
        onReplaceKey={openManageDialog}
        replaceKeyButtonRef={manageButtonRef}
      />
    );
  }
  // Registry artifacts first, then the ones that ship with Prowler.
  const exploreCount = model.artifacts.length + model.builtinArtifacts.length;
  const renderCatalogCard = (artifact: RegistryMarketplaceArtifact) => (
    <li key={artifact.normalizedName}>
      <RegistryArtifactCard
        artifact={artifact}
        pendingAddName={pendingAddName}
        onAdd={() => handleAdd(artifact)}
        onRemove={(trigger) =>
          openRemoveDialog(catalogRemoveTarget(artifact), trigger)
        }
      />
    </li>
  );
  return (
    <div className="space-y-6">
      <h1 className="sr-only">Registry marketplace</h1>
      <RegistryPageIntro
        errorMessage={accessDialogMode ? undefined : operationMessage}
      />
      {refreshMessage && (
        <Alert variant="warning">
          <AlertDescription>{refreshMessage}</AlertDescription>
        </Alert>
      )}
      <Tabs
        onValueChange={(value) => setActiveTab(value as RegistryTab)}
        value={activeTab}
      >
        <div className="border-border-neutral-secondary flex items-center justify-between gap-2 border-b">
          <div className="min-w-0">
            <TabsList>
              <TabsTrigger
                adornment={
                  <Badge size="sm" variant="tag">
                    {state.catalog.artifacts.length}
                  </Badge>
                }
                value={REGISTRY_TAB.EXPLORE}
              >
                All
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
          <div className="flex shrink-0 items-center gap-2">
            <Button
              aria-label="Refresh Registry"
              aria-busy={isRefreshing}
              disabled={
                isRefreshing || Boolean(pendingOperation || pendingAddName)
              }
              onClick={requestRefresh}
              size="sm"
              type="button"
              variant="ghost"
            >
              <RefreshCw aria-hidden />
              <span className="hidden sm:inline">
                {isRefreshing ? "Refreshing…" : "Refresh"}
              </span>
            </Button>
            <Button
              aria-label="Registry API key"
              onClick={openManageDialog}
              ref={manageButtonRef}
              size="sm"
              type="button"
              variant="ghost"
            >
              <KeyRound aria-hidden />
              <span className="hidden sm:inline">API key</span>
            </Button>
          </div>
        </div>
        <TabsContent className="space-y-4 pt-4" value={REGISTRY_TAB.EXPLORE}>
          <RegistryToolbar
            filters={filters}
            onFiltersChange={setFilters}
            onSortChange={setSort}
            providers={model.providers}
            resultsCount={exploreCount}
            sort={sort}
          />
          {state.catalog.artifacts.length === 0 ? (
            <RegistryEmptyState
              icon={<PackageSearch />}
              title="No Registry artifacts are available."
              description="Published artifacts will appear here when the Registry catalog is available."
              actionLabel="Refresh catalog"
              onAction={requestRefresh}
            />
          ) : exploreCount === 0 ? (
            <RegistryEmptyState
              icon={<SearchX />}
              title="No artifacts match the current filters."
              description="Try another search or clear your filters to explore the catalog."
              actionLabel="Clear filters"
              onAction={() => setFilters({})}
            />
          ) : (
            <>
              {model.artifacts.length > 0 && (
                <RegistryArtifactGrid>
                  {model.artifacts.map(renderCatalogCard)}
                </RegistryArtifactGrid>
              )}
              {model.builtinArtifacts.length > 0 && (
                <section
                  aria-labelledby="registry-builtin-heading"
                  className="space-y-3 pt-2"
                >
                  <h2
                    id="registry-builtin-heading"
                    className="text-text-neutral-secondary text-sm font-medium"
                  >
                    Included in Prowler
                  </h2>
                  <RegistryArtifactGrid>
                    {model.builtinArtifacts.map(renderCatalogCard)}
                  </RegistryArtifactGrid>
                </section>
              )}
            </>
          )}
        </TabsContent>
        <TabsContent className="space-y-4 pt-4" value={REGISTRY_TAB.MINE}>
          {model.myArtifacts.length === 0 ? (
            <RegistryEmptyState
              icon={<PackageSearch />}
              title="No artifacts in this workspace yet."
              description="Explore the catalog to add providers or checks to this workspace."
              actionLabel="Explore artifacts"
              onAction={() => setActiveTab(REGISTRY_TAB.EXPLORE)}
            />
          ) : (
            <RegistryArtifactGrid>
              {model.myArtifacts.map((myArtifact) => (
                <li key={myArtifact.normalizedName}>
                  {myArtifact.catalogArtifact ? (
                    <RegistryArtifactCard
                      artifact={myArtifact.catalogArtifact}
                      pendingAddName={pendingAddName}
                      onAdd={() => handleAdd(myArtifact.catalogArtifact!)}
                      onRemove={(trigger) =>
                        openRemoveDialog(
                          catalogRemoveTarget(myArtifact.catalogArtifact!),
                          trigger,
                        )
                      }
                    />
                  ) : (
                    <RegistryTenantArtifactCard
                      extendsProviderSlugs={myArtifact.extendsProviderSlugs}
                      normalizedName={myArtifact.normalizedName}
                      onRemove={(trigger) =>
                        openRemoveDialog(
                          {
                            normalizedName: myArtifact.normalizedName,
                            label: myArtifact.normalizedName,
                          },
                          trigger,
                        )
                      }
                      resolvedVersion={myArtifact.resolvedVersion}
                    />
                  )}
                </li>
              ))}
            </RegistryArtifactGrid>
          )}
        </TabsContent>
      </Tabs>
      {accessDialog}
      <RegistryRemoveDialog
        artifactLabel={removeTarget?.label}
        error={removeError}
        isPending={pendingOperation === REGISTRY_PENDING_OPERATION.REMOVE}
        onConfirm={() =>
          removeTarget && handleRemove(removeTarget.normalizedName)
        }
        onOpenChange={(open) => {
          if (!open && pendingOperation !== REGISTRY_PENDING_OPERATION.REMOVE) {
            setRemoveError(undefined);
            setRemoveTarget(undefined);
          }
        }}
        onViewProviders={() => router.push("/providers")}
        open={removeTarget !== undefined}
        returnFocusRef={removeTriggerRef}
      />
    </div>
  );
}
