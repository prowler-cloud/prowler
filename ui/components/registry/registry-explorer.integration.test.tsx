import { http, HttpResponse } from "msw";
import { useRouter } from "next/navigation";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { page, userEvent } from "vitest/browser";

import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import type {
  RegistryArtifactRemovalResult,
  RegistryBootstrapState,
} from "@/types/registry";

import { RegistryArtifactCard } from "./registry-artifact-card";
import { RegistryExplorer } from "./registry-explorer";

vi.mock("next/navigation", async () => {
  const { useSyncExternalStore } = await import("react");
  const router = { replace: vi.fn(), push: vi.fn(), refresh: vi.fn() };
  const subscribe = (callback: () => void) => {
    window.addEventListener("popstate", callback);
    return () => window.removeEventListener("popstate", callback);
  };
  return {
    useRouter: () => router,
    usePathname: () => "/registry",
    useSearchParams: () =>
      new URLSearchParams(
        useSyncExternalStore(
          subscribe,
          () => window.location.search,
          () => "",
        ),
      ),
  };
});
const originalReplaceState = window.history.replaceState.bind(window.history);

const {
  disconnectRegistryCredentialMock,
  executeRegistryArtifactAdditionMock,
  refreshRegistryCollectionsMock,
  refreshRegistryCredentialMock,
  removeRegistryArtifactMock,
  submitRegistryCredentialMock,
  trackAndPollTaskMock,
} = vi.hoisted(() => ({
  disconnectRegistryCredentialMock: vi.fn(),
  executeRegistryArtifactAdditionMock: vi.fn(),
  refreshRegistryCollectionsMock: vi.fn(),
  refreshRegistryCredentialMock: vi.fn(),
  removeRegistryArtifactMock: vi.fn(),
  submitRegistryCredentialMock: vi.fn(),
  trackAndPollTaskMock: vi.fn(),
}));

vi.mock("@/actions/registry/registry", () => ({
  disconnectRegistryCredential: disconnectRegistryCredentialMock,
  getRegistryBootstrap: vi.fn(),
  refreshRegistryCollections: refreshRegistryCollectionsMock,
  refreshRegistryCredential: refreshRegistryCredentialMock,
  removeRegistryArtifact: removeRegistryArtifactMock,
  submitRegistryCredential: submitRegistryCredentialMock,
}));

// The credential flow watches its validation task through the house task
// watcher; integration tests drive settlement through this mock the same way
// `lib/jira-dispatch-execution.test.ts` does.
vi.mock("@/lib/registry/artifact-execution", () => ({
  executeRegistryArtifactAddition: executeRegistryArtifactAdditionMock,
}));

vi.mock("@/store/task-watcher/store", () => ({
  TASK_WATCHER_STATUS: { PENDING: "pending", READY: "ready", ERROR: "error" },
  trackAndPollTask: trackAndPollTaskMock,
  useTaskWatcherStore: (selector: (state: { tasks: {} }) => unknown) =>
    selector({ tasks: {} }),
}));

// The integration setup mocks `next/navigation` with a module-level router,
// so this "hook" is a plain function returning the shared router spies and
// is safe to call outside a component.
// eslint-disable-next-line react-hooks/rules-of-hooks
const registryRouter = useRouter();

const onboardingState: RegistryBootstrapState = {
  status: "onboarding",
  credential: {
    configured: false,
    isValid: false,
    scopes: [],
    validationPending: false,
  },
  tenantArtifacts: [],
};

const validationPendingState: RegistryBootstrapState = {
  status: "validation_pending",
  credential: {
    configured: true,
    isValid: false,
    scopes: [],
    validationPending: true,
  },
  tenantArtifacts: [],
};

const submittedResult = (priorConfigured = false) => ({
  status: "submitted" as const,
  taskId: "registry-task-1",
  priorConfigured,
});

const readyState: RegistryBootstrapState = {
  status: "ready",
  credential: {
    configured: true,
    isValid: true,
    scopes: ["catalog:read"],
    validationPending: false,
  },
  catalog: {
    status: "complete",
    artifacts: [
      {
        normalizedName: "aws-guard",
        name: "AWS guard",
        description: "Already added artifact",
        latestVersion: "1.2.3",
        providers: ["aws"],
        isVerified: true,
        isOfficial: true,
        isBuiltin: false,
        isMeta: false,
        hasProvider: true,
        isInstallable: true,
        hasChecks: true,
        hasCompliance: false,
        versionCount: 2,
        totalDownloads: 12,
        owners: [
          {
            name: "Prowler",
            type: "organization",
            logoUrl: "https://cdn.example/prowler-logo.png",
          },
        ],
      },
      {
        normalizedName: "later-guard",
        name: "Later guard",
        description: "Artifact collected from a later page",
        latestVersion: "2.0.0",
        providers: ["azure"],
        isVerified: false,
        isOfficial: false,
        isBuiltin: false,
        isMeta: false,
        hasProvider: true,
        isInstallable: true,
        hasChecks: true,
        hasCompliance: true,
        versionCount: 1,
        totalDownloads: 3,
        owners: [],
      },
      {
        normalizedName: "cloud-guard",
        name: "Cloud guard",
        description: "Multi-provider artifact",
        latestVersion: "3.0.0",
        providers: ["aws", "gcp"],
        isVerified: true,
        isOfficial: true,
        isBuiltin: false,
        isMeta: true,
        hasProvider: true,
        isInstallable: true,
        hasChecks: true,
        hasCompliance: true,
        versionCount: 4,
        totalDownloads: 42,
        owners: [{ name: "Registry team", type: "organization" }],
      },
    ],
  },
  tenantArtifacts: [
    { normalizedName: "aws-guard", versionSpec: "latest" },
    {
      normalizedName: "saved-artifact",
      versionSpec: "latest",
      resolvedVersion: "1.0.0",
    },
  ],
};

async function expectRedirectedToProfile() {
  await expect
    .poll(() => vi.mocked(registryRouter.replace).mock.calls)
    .toEqual([["/profile"]]);
}

const incompleteState: RegistryBootstrapState = {
  status: "incomplete",
  catalog: { status: "incomplete", reason: "page_failed", collectedCount: 100 },
};

// The header button shares this name, so look inside the open dialog.
const registryKeyInput = () =>
  page.getByRole("dialog").getByLabelText("Registry API key");

function cardFor(name: string) {
  const card = Array.from(document.querySelectorAll("li")).find((item) =>
    item.textContent?.includes(name),
  );
  if (!card) throw new Error(`Expected a rendered card for ${name}`);
  return card;
}

describe("RegistryExplorer", () => {
  it("refreshes catalog and installed versions when switching tabs", async () => {
    // Given
    refreshRegistryCollectionsMock.mockResolvedValue({
      status: "complete",
      catalog: readyState.catalog,
      tenantArtifacts: [
        {
          normalizedName: "aws-guard",
          versionSpec: "latest",
          resolvedVersion: "1.0.0",
        },
      ],
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    // When
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    // Then
    await expect
      .element(
        screen.getByRole("button", { name: "Update AWS guard to 1.2.3" }),
      )
      .toBeVisible();
    expect(refreshRegistryCollectionsMock).toHaveBeenCalled();
  });

  it("coalesces manual, tab and focus refreshes while preserving filters", async () => {
    // Given
    let resolveRefresh!: (value: unknown) => void;
    refreshRegistryCollectionsMock.mockReturnValue(
      new Promise((resolve) => {
        resolveRefresh = resolve;
      }),
    );
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByLabelText("Search artifacts").fill("AWS");
    // When: the tab change also requests a refresh, sharing any focus read.
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    window.dispatchEvent(new Event("focus"));
    await screen.getByRole("tab", { name: /All/ }).click();
    // Then
    await expect
      .element(screen.getByRole("button", { name: "Refresh Registry" }))
      .toBeDisabled();
    expect(document.body.textContent).toContain("Refreshing…");
    expect(refreshRegistryCollectionsMock).toHaveBeenCalledOnce();
    expect(cardFor("AWS guard")).toBeTruthy();
    resolveRefresh({
      status: "complete",
      catalog: {
        ...readyState.catalog,
        artifacts: readyState.catalog.artifacts.map((artifact) => ({
          ...artifact,
          latestVersion: "2.0.0",
        })),
      },
      tenantArtifacts: [
        {
          normalizedName: "aws-guard",
          versionSpec: "latest",
          resolvedVersion: "1.2.3",
        },
      ],
    });
    await expect
      .element(
        screen.getByRole("button", { name: "Update AWS guard to 2.0.0" }),
      )
      .toBeVisible();
    await expect
      .element(screen.getByLabelText("Search artifacts"))
      .toHaveValue("AWS");
    await expect
      .element(screen.getByRole("button", { name: "Refresh Registry" }))
      .toBeEnabled();
    expect(document.body.textContent).not.toContain("Later guard");
  });

  it("loads a newly published artifact from the Refresh button without navigating", async () => {
    // Given
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    refreshRegistryCollectionsMock.mockResolvedValue({
      status: "complete",
      tenantArtifacts: readyState.tenantArtifacts,
      catalog: {
        ...readyState.catalog,
        artifacts: [
          ...readyState.catalog.artifacts,
          {
            ...readyState.catalog.artifacts[0],
            normalizedName: "new-artifact",
            name: "New artifact",
          },
        ],
      },
    });
    // When
    await screen.getByRole("button", { name: "Refresh Registry" }).click();
    // Then
    await expect
      .element(screen.getByText("New artifact", { exact: true }))
      .toBeVisible();
    expect(window.location.pathname).toBe("/registry");
    expect(registryRouter.refresh).not.toHaveBeenCalled();
  });

  it.each(["error", "incomplete"])(
    "preserves the last complete snapshot after a %s refresh and allows retry",
    async (status) => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );
      refreshRegistryCollectionsMock.mockResolvedValue({
        status,
        reason: "page_failed",
        collectedCount: 1,
      });
      // When
      await screen.getByRole("button", { name: "Refresh Registry" }).click();
      // Then
      await expect
        .element(screen.getByRole("alert"))
        .toHaveTextContent("Showing the last available data.");
      expect(cardFor("AWS guard")).toBeTruthy();
      expect(cardFor("Later guard")).toBeTruthy();
      await expect
        .element(screen.getByRole("button", { name: "Refresh Registry" }))
        .toBeEnabled();
      // When / Then
      refreshRegistryCollectionsMock.mockResolvedValue({
        status: "complete",
        catalog: readyState.catalog,
        tenantArtifacts: [],
      });
      await screen.getByRole("button", { name: "Refresh Registry" }).click();
      await expect
        .element(screen.getByRole("button", { name: "Add AWS guard" }))
        .toBeVisible();
      await expect.element(screen.getByRole("alert")).not.toBeInTheDocument();
    },
  );

  it("discards a stale refresh and waits for an update before reading again", async () => {
    // Given
    const installed = {
      normalizedName: "aws-guard",
      versionSpec: "latest",
      resolvedVersion: "1.0.0",
    };
    let stale!: (value: unknown) => void;
    let update!: (value: unknown) => void;
    let fresh!: (value: unknown) => void;
    refreshRegistryCollectionsMock
      .mockReturnValueOnce(
        new Promise((resolve) => {
          stale = resolve;
        }),
      )
      .mockReturnValueOnce(
        new Promise((resolve) => {
          fresh = resolve;
        }),
      );
    executeRegistryArtifactAdditionMock.mockReturnValue(
      new Promise((resolve) => {
        update = resolve;
      }),
    );
    const screen = await render(
      <RegistryExplorer
        initialState={{ ...readyState, tenantArtifacts: [installed] }}
      />,
    );
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    // When
    await screen
      .getByRole("button", { name: "Update AWS guard to 1.2.3" })
      .click();
    window.dispatchEvent(new Event("focus"));
    stale({
      status: "complete",
      catalog: { status: "complete", artifacts: [] },
      tenantArtifacts: [],
    });
    // Then: old reads cannot erase an in-flight update.
    await expect
      .element(
        screen.getByRole("button", { name: "Update AWS guard to 1.2.3" }),
      )
      .toBeDisabled();
    expect(refreshRegistryCollectionsMock).toHaveBeenCalledOnce();
    const tenantArtifacts = [{ ...installed, resolvedVersion: "1.2.3" }];
    update({ status: "confirmed", tenantArtifacts });
    await expect
      .element(screen.getByText("Added", { exact: true }))
      .toBeVisible();
    await expect
      .poll(() => refreshRegistryCollectionsMock.mock.calls.length)
      .toBe(2);
    fresh({ status: "complete", catalog: readyState.catalog, tenantArtifacts });
    await expect
      .element(screen.getByRole("button", { name: "Refresh Registry" }))
      .toBeEnabled();
    expect(cardFor("AWS guard").textContent).not.toContain("1.0.0");
    await expect
      .element(screen.getByText("Added", { exact: true }))
      .toBeVisible();
  });

  it("keeps the list usable when the refresh request rejects", async () => {
    // Given
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    refreshRegistryCollectionsMock.mockRejectedValue(
      new Error("Network failure"),
    );
    // When
    await screen.getByRole("button", { name: "Refresh Registry" }).click();
    // Then
    await expect
      .element(screen.getByRole("alert"))
      .toHaveTextContent("Registry could not be refreshed.");
    await expect
      .element(screen.getByRole("button", { name: "Refresh Registry" }))
      .toBeEnabled();
    expect(cardFor("AWS guard")).toBeTruthy();
  });

  it("re-renders the page when a refresh reports a lapsed subscription", async () => {
    // Given
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    refreshRegistryCollectionsMock.mockResolvedValue({
      status: "subscription_required",
    });
    // When
    await screen.getByRole("button", { name: "Refresh Registry" }).click();
    // Then
    // The mocked router never swaps the page, so the explorer may refresh again.
    await expect
      .poll(() => vi.mocked(registryRouter.refresh).mock.calls.length)
      .toBeGreaterThanOrEqual(1);
    expect(vi.mocked(registryRouter.replace)).not.toHaveBeenCalled();
    await expect
      .element(screen.getByRole("button", { name: "Refresh Registry" }))
      .toBeEnabled();
    expect(document.body.textContent).not.toContain(
      "Registry could not be refreshed.",
    );
  });

  it.each(["access_denied", "reconnect", "onboarding"])(
    "honors %s from a collection refresh",
    async (status) => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );
      refreshRegistryCollectionsMock.mockResolvedValue({ status });
      // When
      await screen.getByRole("button", { name: "Refresh Registry" }).click();
      // Then
      if (status === "access_denied") {
        await expectRedirectedToProfile();
      } else {
        await expect
          .element(
            screen.getByRole("button", {
              name: status === "reconnect" ? "Replace key" : "Connect API key",
            }),
          )
          .toBeVisible();
      }
    },
  );

  it("retries a deferred refresh after credential replacement fails", async () => {
    // Given
    let stale!: (value: unknown) => void;
    refreshRegistryCollectionsMock
      .mockReturnValueOnce(
        new Promise((resolve) => {
          stale = resolve;
        }),
      )
      .mockResolvedValue({
        status: "complete",
        catalog: readyState.catalog,
        tenantArtifacts: [],
      });
    submitRegistryCredentialMock.mockResolvedValue({
      status: "replacement_failed",
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    // When
    await screen.getByRole("button", { name: "Registry API key" }).click();
    await registryKeyInput().fill("synthetic-replacement-key");
    await screen.getByRole("button", { name: "Replace key" }).click();
    await expect.element(screen.getByRole("alert")).toBeVisible();
    stale({
      status: "complete",
      catalog: readyState.catalog,
      tenantArtifacts: readyState.tenantArtifacts,
    });
    // Then
    await expect
      .poll(() => refreshRegistryCollectionsMock.mock.calls.length)
      .toBe(2);
    await screen.getByRole("button", { name: "Close", exact: true }).click();
    await expect
      .element(screen.getByText("No artifacts in this workspace yet."))
      .toBeVisible();
  });

  it("does not restore a removed artifact from an earlier refresh", async () => {
    // Given
    let stale!: (value: unknown) => void;
    refreshRegistryCollectionsMock
      .mockReturnValueOnce(
        new Promise((resolve) => {
          stale = resolve;
        }),
      )
      .mockResolvedValue({
        status: "complete",
        catalog: readyState.catalog,
        tenantArtifacts: [],
      });
    removeRegistryArtifactMock.mockResolvedValue({
      status: "confirmed",
      tenantArtifacts: [],
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    // When
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();
    await screen.getByRole("button", { name: "Remove", exact: true }).click();
    await expect
      .element(screen.getByText("No artifacts in this workspace yet."))
      .toBeVisible();
    stale({
      status: "complete",
      catalog: readyState.catalog,
      tenantArtifacts: readyState.tenantArtifacts,
    });
    // Then
    await expect
      .element(screen.getByRole("button", { name: "Refresh Registry" }))
      .toBeEnabled();
    await expect
      .element(screen.getByText("No artifacts in this workspace yet."))
      .toBeVisible();
    expect(refreshRegistryCollectionsMock).toHaveBeenCalledTimes(2);
  });

  it("refreshes on returning focus and ignores focus while hidden", async () => {
    // Given
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    const visibility = vi
      .spyOn(document, "visibilityState", "get")
      .mockReturnValue("hidden");
    refreshRegistryCollectionsMock.mockClear();
    // When / Then
    window.dispatchEvent(new Event("focus"));
    expect(refreshRegistryCollectionsMock).not.toHaveBeenCalled();
    refreshRegistryCollectionsMock.mockResolvedValue({
      status: "complete",
      catalog: readyState.catalog,
      tenantArtifacts: [
        {
          normalizedName: "aws-guard",
          versionSpec: "latest",
          resolvedVersion: "1.0.0",
        },
      ],
    });
    visibility.mockReturnValue("visible");
    window.dispatchEvent(new Event("focus"));
    await expect
      .element(
        screen.getByRole("button", { name: "Update AWS guard to 1.2.3" }),
      )
      .toBeVisible();
  });

  it.each([
    [
      { status: "refused", message: "This version has been withdrawn." },
      "This version has been withdrawn.",
    ],
    [
      { status: "unavailable" },
      "The Registry operation could not be completed. Try again.",
    ],
    [
      { status: "refresh_failed" },
      "Update could not be confirmed. Refresh Registry before retrying.",
    ],
  ])(
    "keeps Update available after %j and allows retry",
    async (result, message) => {
      // Given
      const installed = {
        normalizedName: "aws-guard",
        versionSpec: "latest",
        resolvedVersion: "1.0.0",
      };
      executeRegistryArtifactAdditionMock.mockResolvedValue(result);
      const screen = await render(
        <RegistryExplorer
          initialState={{ ...readyState, tenantArtifacts: [installed] }}
        />,
      );
      // When
      await screen
        .getByRole("button", { name: "Update AWS guard to 1.2.3" })
        .click();
      // Then
      await expect
        .element(screen.getByText(message as string, { exact: true }))
        .toBeVisible();
      await expect
        .element(
          screen.getByRole("button", { name: "Update AWS guard to 1.2.3" }),
        )
        .toBeEnabled();
      expect(cardFor("AWS guard").textContent).toContain("1.0.0");
      expect(document.body.textContent).not.toContain("Artifact updated");
      // When / Then: retry can complete normally.
      executeRegistryArtifactAdditionMock.mockResolvedValue({
        status: "confirmed",
        tenantArtifacts: [{ ...installed, resolvedVersion: "1.2.3" }],
      });
      await screen
        .getByRole("button", { name: "Update AWS guard to 1.2.3" })
        .click();
      await expect
        .element(screen.getByText("Added", { exact: true }))
        .toBeVisible();
      await expect
        .element(screen.getByText(message as string, { exact: true }))
        .not.toBeInTheDocument();
    },
  );

  it("updates an installed artifact to the displayed version and returns to Added", async () => {
    // Given
    const installed = {
      normalizedName: "aws-guard",
      versionSpec: "latest",
      resolvedVersion: "1.0.0",
    };
    let complete!: (value: unknown) => void;
    executeRegistryArtifactAdditionMock.mockReturnValue(
      new Promise((resolve) => {
        complete = resolve;
      }),
    );
    const screen = await render(
      <RegistryExplorer
        initialState={{ ...readyState, tenantArtifacts: [installed] }}
      />,
    );
    // When
    await screen
      .getByRole("button", { name: "Update AWS guard to 1.2.3" })
      .click();
    // Then
    expect(executeRegistryArtifactAdditionMock).toHaveBeenCalledWith({
      normalizedName: "aws-guard",
      versionSpec: "1.2.3",
      operation: "update",
    });
    await expect
      .element(
        screen.getByRole("button", { name: "Update AWS guard to 1.2.3" }),
      )
      .toBeDisabled();
    await expect
      .element(screen.getByRole("button", { name: "Remove AWS guard" }))
      .toBeDisabled();
    expect(document.body.textContent).toContain("Updating…");
    complete({
      status: "confirmed",
      tenantArtifacts: [{ ...installed, resolvedVersion: "1.2.3" }],
    });
    await expect
      .element(screen.getByText("Added", { exact: true }))
      .toBeVisible();
    await expect
      .element(screen.getByRole("button", { name: "Remove AWS guard" }))
      .toBeEnabled();
    expect(cardFor("AWS guard").textContent).not.toContain("1.0.0");
  });

  it("offers key replacement when the configured Registry rejects access", async () => {
    const screen = await render(
      <RegistryExplorer initialState={{ status: "reconnect" }} />,
    );
    const title = screen.getByRole("heading", {
      name: "Reconnect the Registry",
    });
    await expect.element(title).toBeVisible();
    // Both actions share one panel, Replace key first.
    const panel = title.element().closest("section");
    expect(
      Array.from(panel!.querySelectorAll("button"), (b) => b.textContent),
    ).toEqual(["Replace key", "Retry"]);
    await screen.getByRole("button", { name: "Replace key" }).click();
    await expect
      .element(screen.getByRole("dialog", { name: "Registry API key" }))
      .toHaveTextContent("Rejected by the Registry");
    await expect.element(registryKeyInput()).toBeEnabled();
  });

  beforeEach(() => {
    worker.use(
      http.get(
        "https://cdn.example/prowler-logo.png",
        () =>
          new HttpResponse(
            '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"><rect width="20" height="20" fill="black"/></svg>',
            { headers: { "Content-Type": "image/svg+xml" } },
          ),
      ),
      http.get(
        "https://cdn.example/expired.png",
        () => new HttpResponse(null, { status: 403 }),
      ),
    );
    originalReplaceState(null, "", "/registry");
    vi.spyOn(window.history, "replaceState").mockImplementation(
      (data, unused, url) => {
        originalReplaceState(data, unused, url);
        window.dispatchEvent(new PopStateEvent("popstate"));
      },
    );
    disconnectRegistryCredentialMock.mockReset();
    executeRegistryArtifactAdditionMock.mockReset();
    refreshRegistryCollectionsMock.mockReset();
    refreshRegistryCollectionsMock.mockResolvedValue({
      status: "complete",
      catalog: readyState.catalog,
      tenantArtifacts: readyState.tenantArtifacts,
    });
    refreshRegistryCredentialMock.mockReset();
    removeRegistryArtifactMock.mockReset();
    submitRegistryCredentialMock.mockReset();
    trackAndPollTaskMock.mockReset();
    trackAndPollTaskMock.mockResolvedValue({
      status: "ready",
      result: { stored: true, error: null },
    });
    vi.mocked(registryRouter.replace).mockClear();
  });

  describe("when Registry access is not connected", () => {
    it("shows the credential banner instead of a catalog", async () => {
      // Given / When
      await render(<RegistryExplorer initialState={onboardingState} />);

      // Then
      expect(document.body.textContent).toContain(
        "Connect your Registry API key",
      );
      expect(document.body.textContent).toContain(
        "A Registry API key is needed to add artifacts to this workspace.",
      );
      expect(document.body.textContent).not.toContain("stay installed");
      expect(document.body.textContent).not.toContain(
        "Explore Prowler Registry",
      );
      expect(document.body.textContent).not.toContain("Search artifacts");
    });

    it("links the banner to the configured Registry", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer
          initialState={onboardingState}
          registryUrl="https://registry.internal.test/"
        />,
      );

      // Then
      await expect
        .element(
          screen.getByRole("link", {
            name: "Explore Prowler Registry (opens in a new tab)",
          }),
        )
        .toHaveAttribute("href", "https://registry.internal.test/");
    });

    it("connects, not manages, a key when the catalog loads without one", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer
          initialState={{
            ...readyState,
            credential: onboardingState.credential,
          }}
          registryUrl="https://registry.internal.test/"
        />,
      );

      // Then: an inline callout sits above the catalog.
      await expect
        .element(
          screen.getByText(
            "Artifacts open to every workspace install without a key. Connect a Registry API key to add the ones that need approved access.",
          ),
        )
        .toBeVisible();
      expect(cardFor("AWS guard")).toBeTruthy();

      // When
      const keyButton = screen.getByRole("button", {
        name: "Registry API key",
      });
      await keyButton.click();

      // Then
      await expect
        .element(
          screen.getByRole("dialog", { name: "Connect Registry API key" }),
        )
        .toBeVisible();
      await expect
        .element(screen.getByRole("button", { name: "Disconnect" }))
        .not.toBeInTheDocument();

      // When
      await userEvent.keyboard("{Escape}");

      // Then
      await expect.element(keyButton).toHaveFocus();
    });

    it("manages, not connects, a stored key the Registry rejected", async () => {
      // Given: the catalog loads without a valid tenant key, but one is stored
      const screen = await render(
        <RegistryExplorer
          initialState={{
            ...readyState,
            credential: {
              configured: true,
              isValid: false,
              scopes: [],
              validationPending: false,
            },
          }}
        />,
      );

      // When
      await screen.getByRole("button", { name: "Registry API key" }).click();

      // Then: the stored key can be replaced or disconnected
      const dialog = screen.getByRole("dialog", { name: "Registry API key" });
      await expect
        .element(dialog.getByText("Rejected by the Registry"))
        .toBeVisible();
      await expect
        .element(screen.getByRole("button", { name: "Disconnect" }))
        .toBeVisible();
    });

    it("asks to replace, not connect, a stored key the Registry rejected", async () => {
      // Given: the catalog loads without a valid tenant key, but one is stored
      const screen = await render(
        <RegistryExplorer
          initialState={{
            ...readyState,
            credential: {
              configured: true,
              isValid: false,
              scopes: [],
              validationPending: false,
            },
          }}
        />,
      );

      // Then: the callout names the rejected key instead of asking for one
      await expect
        .element(
          screen.getByText(
            "The Registry rejected this workspace's API key. Replace it to add the artifacts that need approved access.",
          ),
        )
        .toBeVisible();
      await expect
        .element(screen.getByRole("button", { name: "Connect API key" }))
        .not.toBeInTheDocument();

      // When
      const replaceButton = screen.getByRole("button", { name: "Replace key" });
      await replaceButton.click();

      // Then: the same dialog the header button opens
      const dialog = screen.getByRole("dialog", { name: "Registry API key" });
      await expect
        .element(dialog.getByText("Rejected by the Registry"))
        .toBeVisible();

      // When
      await userEvent.keyboard("{Escape}");

      // Then
      await expect.element(replaceButton).toHaveFocus();
    });

    it("lets a replacement key supersede a pending validation from the banner", async () => {
      // Given: a validation that never settled must not dead-end the user
      submitRegistryCredentialMock.mockResolvedValue(submittedResult(true));
      refreshRegistryCredentialMock.mockResolvedValue({
        status: "status",
        credential: readyState.credential,
      });
      refreshRegistryCollectionsMock.mockResolvedValue({
        status: "complete",
        catalog: readyState.catalog,
        tenantArtifacts: readyState.tenantArtifacts,
      });
      const screen = await render(
        <RegistryExplorer initialState={validationPendingState} />,
      );

      // Pending validation leaves the form available for a replacement.
      expect(document.body.textContent).toContain(
        "Validating your Registry API key",
      );
      // aria-busy would hold back the live region's announcement for good.
      const validatingPanel = Array.from(
        document.querySelectorAll('[aria-live="polite"]'),
      ).find((element) =>
        element.textContent?.includes("Validating your Registry API key"),
      );
      expect(validatingPanel).toBeTruthy();
      expect(validatingPanel?.hasAttribute("aria-busy")).toBe(false);
      await expect
        .element(screen.getByRole("button", { name: "Use a different key" }))
        .toBeEnabled();
      expect(document.body.textContent).not.toContain("Search artifacts");

      // When
      await screen.getByRole("button", { name: "Use a different key" }).click();
      await registryKeyInput().fill("replacement-key");
      await screen
        .getByRole("button", { name: "Connect", exact: true })
        .click();

      // Then: the replacement POST supersedes the pending validation
      await expect
        .poll(() => submitRegistryCredentialMock.mock.calls)
        .toEqual([["replacement-key"]]);
      await expect
        .element(screen.getByRole("button", { name: "Registry API key" }))
        .toBeVisible();
    });
  });

  it("moves focus into the access dialog and returns it to Connect API key", async () => {
    // Given
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );
    const connectButton = screen.getByRole("button", {
      name: "Connect API key",
    });

    // When
    await connectButton.click();

    // Then
    await expect.element(registryKeyInput()).toHaveFocus();

    // When
    await userEvent.keyboard("{Escape}");

    // Then
    await expect.element(connectButton).toHaveFocus();
  });

  it("returns focus to the API key button when connecting replaces the banner", async () => {
    // Given
    submitRegistryCredentialMock.mockResolvedValue(submittedResult());
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: readyState.credential,
    });
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await registryKeyInput().fill("registry-test-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: the banner that opened the dialog is gone; focus lands on its replacement
    await expect
      .element(screen.getByRole("button", { name: "Registry API key" }))
      .toHaveFocus();
  });

  it("presents the connect dialog with help link and cancel action", async () => {
    // Given
    const screen = await render(
      <RegistryExplorer
        initialState={onboardingState}
        registryUrl="https://registry.private.test/"
      />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();

    // Then
    await expect
      .element(
        screen.getByRole("heading", { name: "Connect Registry API key" }),
      )
      .toBeVisible();
    await expect
      .element(screen.getByRole("link", { name: "Where do I find my key?" }))
      .toHaveAttribute("href", "https://registry.private.test/");

    // When
    await screen.getByRole("button", { name: "Cancel", exact: true }).click();

    // Then
    await expect.element(registryKeyInput()).not.toBeInTheDocument();
  });

  it("preserves the catalog while a watched replacement keeps the form visible and disabled", async () => {
    // Given
    const key = "replacement-key";
    submitRegistryCredentialMock.mockResolvedValue(submittedResult(true));
    trackAndPollTaskMock.mockReturnValue(new Promise(() => {}));
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // The accessible name contains the visible label.
    expect(document.body.textContent).not.toContain("API key connected");
    expect(
      document.querySelector('button[aria-label="Registry API key"]')
        ?.textContent,
    ).toBe("API key");

    // When
    await screen.getByRole("button", { name: "Registry API key" }).click();
    await expect
      .element(
        screen.getByRole("dialog").getByText("Connected", { exact: true }),
      )
      .toBeVisible();
    await registryKeyInput().fill(key);
    await screen.getByRole("button", { name: "Replace key" }).click();

    // Then: the form stays visible; submit shows a disabled Connecting… state
    await expect
      .element(screen.getByRole("button", { name: "Connecting…" }))
      .toBeDisabled();
    await expect.element(registryKeyInput()).toBeDisabled();
    await expect.element(registryKeyInput()).toHaveValue("");
    await expect
      .element(screen.getByRole("button", { name: "Disconnect" }))
      .toBeDisabled();
    expect(document.body.textContent).toContain("Cloud guard");
    expect(document.body.innerHTML).not.toContain(key);
  });

  it("shows the invalid-key error inline below the input and keeps the form retry-capable", async () => {
    // Given
    submitRegistryCredentialMock.mockResolvedValue(submittedResult());
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: onboardingState.credential,
    });
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await registryKeyInput().fill("bad-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: the error renders inside the dialog, below the input
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    await expect
      .poll(() => dialog!.querySelector('[role="alert"]')?.textContent)
      .toContain("This Registry key is invalid. Check it and try again.");
    const input = registryKeyInput().element();
    const alert = dialog!.querySelector('[role="alert"]');
    expect(
      input.compareDocumentPosition(alert!) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();

    // Then: the form is re-enabled for a retry with the key cleared
    await expect
      .element(screen.getByRole("button", { name: "Connect", exact: true }))
      .toBeEnabled();
    await expect.element(registryKeyInput()).toBeEnabled();
    await expect.element(registryKeyInput()).toHaveValue("");
    await expect.element(registryKeyInput()).toHaveFocus();

    // When: a retry submits a fresh key through the same form
    await registryKeyInput().fill("second-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then
    await expect
      .poll(() => submitRegistryCredentialMock.mock.calls)
      .toEqual([["bad-key"], ["second-key"]]);
  });

  it("keeps a retry-capable form after a watcher failure", async () => {
    // Given
    submitRegistryCredentialMock.mockResolvedValue(submittedResult());
    trackAndPollTaskMock.mockRejectedValue(new Error("watcher crashed"));
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await registryKeyInput().fill("registry-test-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    await expect
      .poll(() => dialog!.querySelector('[role="alert"]')?.textContent)
      .toContain("Registry key validation could not be completed. Try again.");
    await expect
      .element(screen.getByRole("button", { name: "Connect", exact: true }))
      .toBeEnabled();
    await expect.element(registryKeyInput()).toBeEnabled();
  });

  it("recovers the form with an inline notice when the watch exhausts without settling", async () => {
    // Given: the watcher gives up while the task is still unsettled (e.g. no
    // worker consumes the queue) — the tracking result resolves as pending
    submitRegistryCredentialMock.mockResolvedValue(submittedResult());
    trackAndPollTaskMock.mockResolvedValue({ status: "pending" });
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: validationPendingState.credential,
    });
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await registryKeyInput().fill("stuck-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: the dialog exits Connecting… into a retry-capable form
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    await expect
      .poll(() => dialog!.querySelector('[role="alert"]')?.textContent)
      .toContain(
        "Registry key validation is taking longer than expected. Try again.",
      );
    await expect
      .element(screen.getByRole("button", { name: "Connect", exact: true }))
      .toBeEnabled();
    await expect.element(registryKeyInput()).toBeEnabled();
    expect(document.body.textContent).toContain(
      "Validating your Registry API key",
    );
  });

  it("recovers the form when the submit RPC rejects instead of stranding Connecting", async () => {
    // Given: the server-action RPC itself rejects (network drop, dev reload)
    submitRegistryCredentialMock.mockRejectedValue(new Error("rpc dropped"));
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await registryKeyInput().fill("registry-test-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: no stranded Connecting… — the form recovers with an inline error
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    await expect
      .poll(() => dialog!.querySelector('[role="alert"]')?.textContent)
      .toContain("Registry key validation could not be completed. Try again.");
    await expect
      .element(screen.getByRole("button", { name: "Connect", exact: true }))
      .toBeEnabled();
    await expect.element(registryKeyInput()).toBeEnabled();
  });

  it("recovers the form when the post-connect collections RPC rejects", async () => {
    // Given: validation succeeds but the collections server action rejects
    submitRegistryCredentialMock.mockResolvedValue(submittedResult());
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: readyState.credential,
    });
    refreshRegistryCollectionsMock.mockRejectedValue(new Error("rpc dropped"));
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await registryKeyInput().fill("registry-test-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: no stranded Connecting… — the form recovers with an inline error
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    await expect
      .poll(() => dialog!.querySelector('[role="alert"]')?.textContent)
      .toContain("Registry collections could not be loaded. Try again.");
    await expect
      .element(screen.getByRole("button", { name: "Connect", exact: true }))
      .toBeEnabled();
  });

  it("keeps the dialog open with an inline notice when validation outlasts the watch", async () => {
    // Given
    submitRegistryCredentialMock.mockResolvedValue(submittedResult());
    trackAndPollTaskMock.mockResolvedValue({
      status: "error",
      error: "The task expired before it could be tracked to completion.",
    });
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: validationPendingState.credential,
    });
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await registryKeyInput().fill("slow-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: an inline notice keeps the retry path available in the dialog
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    await expect
      .poll(() => dialog!.querySelector('[role="alert"]')?.textContent)
      .toContain(
        "Registry key validation is taking longer than expected. Try again.",
      );
    await expect
      .element(screen.getByRole("button", { name: "Connect", exact: true }))
      .toBeEnabled();
    // And the underlying banner reflects the pending validation
    expect(document.body.textContent).toContain(
      "Validating your Registry API key",
    );
  });

  it("trims and resets a write-only key before loading authoritative collections", async () => {
    // Given
    const key = "registry-test-key";
    let resolveSubmission: ((result: unknown) => void) | undefined;
    submitRegistryCredentialMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveSubmission = resolve;
        }),
    );
    refreshRegistryCredentialMock.mockResolvedValue({
      status: "status",
      credential: readyState.credential,
    });
    refreshRegistryCollectionsMock.mockResolvedValue({
      status: "complete",
      catalog: readyState.catalog,
      tenantArtifacts: readyState.tenantArtifacts,
    });
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await registryKeyInput().fill(`  ${key}  `);
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: repeat submission is disabled and the key has left the form.
    await expect
      .element(screen.getByRole("button", { name: "Connecting…", exact: true }))
      .toBeDisabled();
    await expect
      .poll(() => submitRegistryCredentialMock.mock.calls)
      .toEqual([[key]]);
    await expect.element(registryKeyInput()).toHaveValue("");
    expect(document.body.innerHTML).not.toContain(key);
    expect(window.location.href).not.toContain(key);
    expect(localStorage.getItem("registry-key")).toBeNull();
    expect(sessionStorage.getItem("registry-key")).toBeNull();

    // When: the accepted task settles through the watcher
    resolveSubmission?.(submittedResult());

    // Then: the explorer lands in ready state and announces the connection
    await expect
      .element(screen.getByRole("tab", { name: /All/ }))
      .toBeVisible();
    await expect.element(registryKeyInput()).not.toBeInTheDocument();
    expect(refreshRegistryCredentialMock).toHaveBeenCalledTimes(1);
    expect(refreshRegistryCollectionsMock).toHaveBeenCalledTimes(1);
  });

  describe("when a Registry action loses authorization", () => {
    it("routes to Profile once when Add is denied", async () => {
      // Given
      executeRegistryArtifactAdditionMock.mockResolvedValue({
        status: "access_denied",
      });
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // When
      await screen.getByRole("button", { name: "Add Cloud guard" }).click();

      // Then
      await expectRedirectedToProfile();
    });

    it("routes to Profile once when Remove is denied", async () => {
      // Given
      removeRegistryArtifactMock.mockResolvedValue({ status: "access_denied" });
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );
      await screen.getByRole("tab", { name: /My artifacts/ }).click();
      await screen.getByRole("button", { name: "Remove AWS guard" }).click();

      // When
      await screen.getByRole("button", { name: "Remove", exact: true }).click();

      // Then
      await expectRedirectedToProfile();
    });

    it("routes to Profile once when credential submission is denied", async () => {
      // Given
      submitRegistryCredentialMock.mockResolvedValue({
        status: "access_denied",
      });
      const screen = await render(
        <RegistryExplorer initialState={onboardingState} />,
      );
      await screen.getByRole("button", { name: "Connect API key" }).click();
      await registryKeyInput().fill("registry-test-key");

      // When
      await screen
        .getByRole("button", { name: "Connect", exact: true })
        .click();

      // Then
      await expectRedirectedToProfile();
    });

    it("routes to Profile once when disconnect is denied", async () => {
      // Given
      disconnectRegistryCredentialMock.mockResolvedValue({
        status: "access_denied",
      });
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );
      await screen.getByRole("button", { name: "Registry API key" }).click();

      // When
      await screen.getByRole("button", { name: "Disconnect" }).click();

      // Then
      await expectRedirectedToProfile();
    });

    it("routes to Profile once when post-connect collection refresh is denied", async () => {
      // Given
      submitRegistryCredentialMock.mockResolvedValue(submittedResult());
      refreshRegistryCredentialMock.mockResolvedValue({
        status: "status",
        credential: readyState.credential,
      });
      refreshRegistryCollectionsMock.mockResolvedValue({
        status: "access_denied",
      });
      const screen = await render(
        <RegistryExplorer initialState={onboardingState} />,
      );
      await screen.getByRole("button", { name: "Connect API key" }).click();
      await registryKeyInput().fill("registry-test-key");

      // When
      await screen
        .getByRole("button", { name: "Connect", exact: true })
        .click();

      // Then
      await expectRedirectedToProfile();
    });
  });

  it("keeps the rendered catalog after a failed credential replacement", async () => {
    // Given
    const key = "replacement-key";
    submitRegistryCredentialMock.mockResolvedValue({
      status: "replacement_failed",
      credential: readyState.credential,
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Registry API key" }).click();
    await registryKeyInput().fill(key);
    await screen.getByRole("button", { name: "Replace key" }).click();

    // Then
    await expect
      .element(screen.getByRole("dialog"))
      .toHaveTextContent("Existing access is unchanged");
    expect(document.body.textContent).toContain("Cloud guard");
    await expect.element(registryKeyInput()).toHaveValue("");
    expect(document.body.innerHTML).not.toContain(key);
  });

  it("recovers and retries when disconnecting Registry rejects", async () => {
    // Given
    disconnectRegistryCredentialMock.mockRejectedValueOnce(
      new Error("Disconnect transport failed"),
    );
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("button", { name: "Registry API key" }).click();

    // When
    await screen.getByRole("button", { name: "Disconnect" }).click();

    // Then
    await expect
      .element(screen.getByRole("alert"))
      .toHaveTextContent(
        "Registry access could not be disconnected. Try again.",
      );
    await expect
      .element(screen.getByRole("button", { name: "Cancel", exact: true }))
      .toBeEnabled();
    expect(document.body.textContent).toContain("Cloud guard");
    expect(document.body.textContent).not.toContain(
      "Disconnect transport failed",
    );

    // When: retry succeeds without reopening the dialog.
    disconnectRegistryCredentialMock.mockResolvedValueOnce({
      status: "disconnected",
      state: onboardingState,
    });
    await screen.getByRole("button", { name: "Disconnect" }).click();

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Connect API key" }))
      .toBeVisible();
  });

  it("shows the keyless catalog after disconnecting when it stays readable without a key", async () => {
    // Given: with the Prowler Cloud key the catalog reads without a tenant key
    const keylessArtifact = {
      ...readyState.catalog.artifacts[0],
      normalizedName: "keyless-guard",
      name: "Keyless guard",
    };
    disconnectRegistryCredentialMock.mockResolvedValue({
      status: "disconnected",
      state: {
        ...readyState,
        credential: onboardingState.credential,
        catalog: {
          status: "complete",
          artifacts: [...readyState.catalog.artifacts, keylessArtifact],
        },
      },
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    const keyButton = screen.getByRole("button", { name: "Registry API key" });

    // When
    await keyButton.click();
    await screen.getByRole("button", { name: "Disconnect" }).click();

    // Then: the keyless catalog replaces the old one and focus stays on the key button
    await expect.element(screen.getByText("Keyless guard")).toBeVisible();
    await expect
      .element(
        screen.getByText(
          "Artifacts open to every workspace install without a key. Connect a Registry API key to add the ones that need approved access.",
        ),
      )
      .toBeVisible();
    await expect.element(keyButton).toHaveFocus();
    expect(refreshRegistryCollectionsMock).not.toHaveBeenCalled();
  });

  it("goes straight to the credential banner after disconnecting Registry access", async () => {
    // Given: without the Prowler Cloud key the catalog needs a tenant key
    disconnectRegistryCredentialMock.mockResolvedValue({
      status: "disconnected",
      state: {
        ...onboardingState,
        tenantArtifacts: readyState.tenantArtifacts,
      },
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Registry API key" }).click();
    await screen.getByRole("button", { name: "Disconnect" }).click();

    // Then: no stale catalog waits for a refresh, and focus lands on Connect
    await expect
      .element(
        screen.getByRole("heading", { name: "Connect your Registry API key" }),
      )
      .toBeVisible();
    expect(document.body.textContent).toContain(
      "The 2 artifacts already in this workspace stay installed.",
    );
    await expect
      .element(screen.getByRole("button", { name: "Connect API key" }))
      .toHaveFocus();
    expect(refreshRegistryCollectionsMock).not.toHaveBeenCalled();
  });

  it("moves focus to Connect API key after disconnecting from the Reconnect panel", async () => {
    // Given
    disconnectRegistryCredentialMock.mockResolvedValue({
      status: "disconnected",
      state: onboardingState,
    });
    const screen = await render(
      <RegistryExplorer initialState={{ status: "reconnect" }} />,
    );

    // When
    await screen.getByRole("button", { name: "Replace key" }).click();
    await screen.getByRole("button", { name: "Disconnect" }).click();

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Connect API key" }))
      .toHaveFocus();
  });

  it("re-renders the page when disconnecting finds a lapsed subscription", async () => {
    // Given
    disconnectRegistryCredentialMock.mockResolvedValue({
      status: "subscription_required",
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Registry API key" }).click();
    await screen.getByRole("button", { name: "Disconnect" }).click();

    // Then: the server page swaps in the paid-plan prompt
    await expect.poll(() => registryRouter.refresh).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).not.toContain(
      "Registry access could not be disconnected",
    );
  });

  describe("when the complete catalog is ready", () => {
    it.each([
      { isBuiltin: true, isInstallable: false },
      {
        isInstallable: false,
        notInstallableReason: "artifact_defines_nothing_usable",
      },
    ])("keeps ineligible artifacts visible without Add: %j", async (flags) => {
      const state: RegistryBootstrapState = {
        ...readyState,
        catalog: {
          ...readyState.catalog,
          artifacts: [
            {
              ...readyState.catalog.artifacts[2],
              normalizedName: "ineligible",
              name: "Ineligible artifact",
              ...flags,
            },
          ],
        },
        tenantArtifacts: [],
      };
      const screen = await render(<RegistryExplorer initialState={state} />);
      expect(document.body.textContent).toContain("Ineligible artifact");
      await expect
        .element(
          screen.getByRole("button", { name: "Add Ineligible artifact" }),
        )
        .not.toBeInTheDocument();
      // Built-ins say so in the action slot instead.
      expect(
        cardFor("Ineligible artifact").textContent?.includes(
          "Included in Prowler",
        ),
      ).toBe("isBuiltin" in flags);
      expect(executeRegistryArtifactAdditionMock).not.toHaveBeenCalled();
    });

    it("keeps an authoritative built-in membership removable", async () => {
      // Given
      removeRegistryArtifactMock.mockResolvedValue({
        status: "confirmed",
        tenantArtifacts: [
          { normalizedName: "saved-artifact", versionSpec: "1.0.0" },
        ],
      });
      const builtInMemberState: RegistryBootstrapState = {
        ...readyState,
        catalog: {
          ...readyState.catalog,
          artifacts: readyState.catalog.artifacts.map((artifact) =>
            artifact.normalizedName === "aws-guard"
              ? { ...artifact, isBuiltin: true }
              : artifact,
          ),
        },
      };
      const screen = await render(
        <RegistryExplorer initialState={builtInMemberState} />,
      );

      // Then
      expect(cardFor("AWS guard").textContent).toContain("Added");
      expect(cardFor("AWS guard").textContent).not.toContain(
        "Included in Prowler",
      );
      const removeButton = screen.getByRole("button", {
        name: "Remove AWS guard",
      });
      await expect.element(removeButton).toBeVisible();

      // When
      await removeButton.click();
      await screen.getByRole("button", { name: "Remove", exact: true }).click();

      // Then
      await expect
        .poll(() => removeRegistryArtifactMock.mock.calls)
        .toEqual([["aws-guard"]]);
    });

    it("switches to authoritative My artifacts and back", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      await expect
        .element(screen.getByRole("img", { name: "Prowler", exact: true }))
        .toBeVisible();
      await expect
        .element(screen.getByText("Prowler", { exact: true }))
        .not.toBeInTheDocument();

      // When
      await screen.getByRole("tab", { name: /My artifacts/ }).click();

      // Then
      await expect
        .poll(() => document.body.textContent)
        .toContain("saved-artifact");
      expect(document.body.textContent).toContain("1.0.0");
      expect(document.body.textContent).not.toContain("Later guard");

      // When
      await screen.getByRole("tab", { name: /All/ }).click();

      await userEvent.keyboard("{Escape}");
      // Then
      await expect
        .poll(() => document.body.textContent)
        .toContain("Later guard");
    });

    it("derives search from all normalized catalog artifacts", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // When
      await screen.getByLabelText("Search artifacts").fill("later");

      // Then
      await expect
        .poll(() => document.body.textContent)
        .toContain("Later guard");
      await expect
        .poll(() => document.body.textContent)
        .not.toContain("Cloud guard");
      expect(document.body.textContent).toContain("1 artifact");
    });

    it("filters complete results by provider", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // When
      await screen.getByLabelText("Filter by provider").click();

      // When
      await screen.getByRole("option", { name: "Azure", exact: true }).click();

      // Then
      await expect
        .poll(() => document.body.textContent)
        .toContain("Later guard");
      await expect
        .poll(() => document.body.textContent)
        .not.toContain("Cloud guard");
    });

    it("combines capability choices and restores the URL with Clear All", async () => {
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );
      await screen.getByLabelText("Filter by capability").click();
      await screen
        .getByRole("option", { name: "Compliance", exact: true })
        .click();
      await userEvent.keyboard("{Escape}");
      await expect
        .poll(() => document.body.textContent)
        .not.toContain("AWS guard");
      expect(
        new URLSearchParams(window.location.search).get("filter[capability]"),
      ).toBe("compliance");
      await screen.getByRole("button", { name: /Clear/ }).click();
      await expect.poll(() => document.body.textContent).toContain("AWS guard");
      expect(window.location.search).toBe("");
    });

    it("sorts by downloads with name order as the default", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );
      const order = () => {
        const text = document.body.textContent ?? "";
        return [
          text.indexOf("Cloud guard"),
          text.indexOf("AWS guard"),
          text.indexOf("Later guard"),
        ];
      };

      // Then: default name order puts AWS guard first
      expect(order()[1]).toBeLessThan(order()[0]);

      // When
      await screen.getByLabelText("Sort artifacts").click();
      await screen.getByRole("option", { name: "Most downloaded" }).click();

      // Then: downloads order puts Cloud guard first
      await expect.poll(() => order()[0] < order()[1]).toBe(true);
      await expect.poll(() => order()[1] < order()[2]).toBe(true);
    });

    it("lists built-in artifacts after the Registry artifacts under their own heading", async () => {
      // Given: a built-in whose name sorts before every Registry artifact
      await render(
        <RegistryExplorer
          initialState={{
            ...readyState,
            catalog: {
              status: "complete",
              artifacts: [
                ...readyState.catalog.artifacts,
                {
                  ...readyState.catalog.artifacts[2],
                  normalizedName: "a-builtin",
                  name: "A built-in",
                  isBuiltin: true,
                  isInstallable: false,
                },
              ],
            },
          }}
        />,
      );

      // Then
      const heading = document.getElementById("registry-builtin-heading")!;
      expect(heading.textContent).toBe("Included in Prowler");
      for (const name of ["AWS guard", "Cloud guard", "Later guard"]) {
        expect(
          cardFor(name).compareDocumentPosition(heading) &
            Node.DOCUMENT_POSITION_FOLLOWING,
        ).toBeTruthy();
      }
      expect(
        heading.compareDocumentPosition(cardFor("A built-in")) &
          Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
      expect(document.body.textContent).toContain("4 artifacts");
    });

    it("shows a complete empty catalog without degrading controls", async () => {
      // Given / When
      const screen = await render(
        <RegistryExplorer
          initialState={{
            ...readyState,
            catalog: { status: "complete", artifacts: [] },
            tenantArtifacts: [],
          }}
        />,
      );

      // Then
      expect(document.body.textContent).toContain(
        "No Registry artifacts are available.",
      );
      await expect
        .element(screen.getByLabelText("Search artifacts"))
        .toBeVisible();
    });

    it("shows four built-in logos, names the rest of them in the overflow and the dynamic ones in text", async () => {
      // Given: six built-in providers interleaved with two dynamic types
      const blendedArtifact = {
        ...readyState.catalog.artifacts[2],
        normalizedName: "blended-guard",
        name: "Blended guard",
        description: "Artifact spanning logos and pills",
        latestVersion: "1.0.0",
        providers: [
          "aws",
          "template",
          "azure",
          "gcp",
          "custom-scan",
          "kubernetes",
          "m365",
          "github",
        ],
      };

      // When
      const screen = await render(
        <RegistryExplorer
          initialState={{
            ...readyState,
            catalog: { status: "complete", artifacts: [blendedArtifact] },
            tenantArtifacts: [],
          }}
        />,
      );

      // Then: the first four built-ins are focusable logos.
      for (const name of ["AWS", "Azure", "Google Cloud", "Kubernetes"]) {
        await expect
          .element(screen.getByRole("img", { name, exact: true }))
          .toHaveAttribute("tabindex", "0");
      }
      // Collapsed providers stay named for keyboard and assistive technology.
      await expect
        .element(
          screen.getByRole("img", {
            name: "2 more: Microsoft 365, GitHub",
          }),
        )
        .toHaveAttribute("tabindex", "0");
      // Dynamic types have no logo of their own, so they read as text.
      const card = page.elementLocator(cardFor("Blended guard"));
      for (const name of ["Template", "Custom Scan"]) {
        await expect
          .element(card.getByText(name, { exact: true }))
          .toBeVisible();
      }
      expect(cardFor("Blended guard").textContent).not.toContain("8 providers");
    });

    it("shows a chip per capability, preserves zero counts, and hides missing values", async () => {
      // Given
      const artifact = {
        ...readyState.catalog.artifacts[0],
        hasCompliance: true,
        isAdded: false,
        updateAvailable: false,
        extendsProviderSlugs: [],
        checkCount: 645,
        complianceCount: 45,
      };
      const card = (overrides: Partial<typeof artifact>) => (
        <RegistryArtifactCard
          artifact={{ ...artifact, ...overrides }}
          onAdd={() => {}}
          onRemove={() => {}}
        />
      );
      const chips = () =>
        Array.from(
          document.querySelectorAll('ul[aria-label="Contents"] > li'),
          (chip) => chip.textContent,
        );
      const screen = await render(card({}));
      const metadata = screen.getByRole("group", { name: "Artifact metadata" });

      // Then: capabilities are chips; version and downloads stay in the footer.
      expect(chips()).toEqual([
        "Provider",
        "645 checks",
        "45 compliance frameworks",
      ]);
      await expect
        .element(metadata.getByText(artifact.latestVersion!, { exact: true }))
        .toBeVisible();
      expect(metadata.element().textContent).toContain("12 downloads");

      // When / Then: a compliance-only artifact gets no checks chip.
      await screen.rerender(
        card({ hasProvider: false, hasChecks: false, checkCount: 0 }),
      );
      expect(chips()).toEqual(["45 compliance frameworks"]);

      // When / Then: zero is a known count for a capability it has.
      await screen.rerender(
        card({ checkCount: 0, complianceCount: 0, totalDownloads: 0 }),
      );
      expect(chips()).toEqual([
        "Provider",
        "0 checks",
        "0 compliance frameworks",
      ]);
      expect(metadata.element().textContent).toContain("0 downloads");

      // When / Then: built-in artifacts show no downloads.
      await screen.rerender(card({ isBuiltin: true, totalDownloads: 0 }));
      expect(metadata.element().textContent).toBe(
        `Version${artifact.latestVersion}`,
      );

      // When / Then: older responses have no counts, rather than zero counts.
      await screen.rerender(
        card({
          checkCount: undefined,
          complianceCount: undefined,
          latestVersion: undefined,
        }),
      );
      expect(chips()).toEqual(["Provider", "Checks", "Compliance"]);
      expect(metadata.element().textContent).toBe("Downloads12 downloads");
    });

    it("recovers the owner image when a fresh URL replaces an expired one", async () => {
      const artifact = {
        ...readyState.catalog.artifacts[0],
        isAdded: false,
        updateAvailable: false,
        extendsProviderSlugs: [],
        owners: [
          {
            name: "Registry team",
            type: "organization",
            logoUrl: "https://cdn.example/expired.png",
          },
        ],
      };
      const screen = await render(
        <RegistryArtifactCard
          artifact={artifact}
          onAdd={() => {}}
          onRemove={() => {}}
        />,
      );
      await expect
        .element(screen.getByText("R", { exact: true }))
        .toBeVisible();
      await screen.rerender(
        <RegistryArtifactCard
          artifact={{
            ...artifact,
            owners: [
              {
                ...artifact.owners[0],
                logoUrl: "https://cdn.example/prowler-logo.png",
              },
            ],
          }}
          onAdd={() => {}}
          onRemove={() => {}}
        />,
      );
      await expect
        .poll(() =>
          document.querySelector(
            'img[src="https://cdn.example/prowler-logo.png"]',
          ),
        )
        .not.toBeNull();
      expect(document.body.textContent).toContain("Registry team");
    });
  });

  it("keeps ordinary Add errors local without redirecting to Profile", async () => {
    // Given
    executeRegistryArtifactAdditionMock.mockResolvedValue({ status: "error" });
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Add Cloud guard" }).click();

    // Then
    await expect
      .element(screen.getByRole("alert"))
      .toHaveTextContent("Registry operation could not be completed");
    await expect
      .element(screen.getByRole("button", { name: "Add Cloud guard" }))
      .toBeEnabled();
    expect(registryRouter.replace).not.toHaveBeenCalled();
  });

  it("adds the latest version directly from the card once confirmed", async () => {
    // Given
    executeRegistryArtifactAdditionMock.mockResolvedValue({
      status: "confirmed",
      tenantArtifacts: [
        { normalizedName: "aws-guard", versionSpec: "latest" },
        { normalizedName: "saved-artifact", versionSpec: "1.0.0" },
        { normalizedName: "cloud-guard", versionSpec: "latest" },
      ],
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    expect(document.body.textContent).not.toContain("Artifact added");

    // When
    await screen.getByRole("button", { name: "Add Cloud guard" }).click();

    // Then
    await expect
      .poll(() => executeRegistryArtifactAdditionMock.mock.calls)
      .toEqual([[{ normalizedName: "cloud-guard" }]]);
    // The confirmed membership now offers Remove instead of Add on the card.
    await expect
      .element(screen.getByRole("button", { name: "Remove Cloud guard" }))
      .toBeVisible();
    await expect
      .element(screen.getByRole("tab", { name: /My artifacts/ }))
      .toHaveTextContent("3");
  });

  it("keeps membership unchanged when an accepted Add cannot be confirmed", async () => {
    // Given
    executeRegistryArtifactAdditionMock.mockResolvedValue({
      status: "refresh_failed",
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Add Cloud guard" }).click();

    // Then
    await expect
      .poll(() => document.body.textContent)
      .toContain("Registry membership could not be confirmed");
    await expect
      .element(screen.getByRole("button", { name: "Add Cloud guard" }))
      .toBeEnabled();
    await expect
      .element(screen.getByRole("tab", { name: /My artifacts/ }))
      .toHaveTextContent("2");
  });

  it("keeps documented Add refusals local without redirecting to Profile", async () => {
    // Given
    executeRegistryArtifactAdditionMock.mockResolvedValue({
      status: "refused",
      message: "This version is not verified and cannot be added.",
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Add Cloud guard" }).click();

    // Then
    await expect
      .poll(() => document.body.textContent)
      .toContain("This version is not verified and cannot be added.");
    await expect
      .element(screen.getByRole("button", { name: "Add Cloud guard" }))
      .toBeEnabled();
    expect(registryRouter.replace).not.toHaveBeenCalled();
  });

  it("disables all Add buttons while an Add confirmation is pending", async () => {
    // Given
    executeRegistryArtifactAdditionMock.mockReturnValue(new Promise(() => {}));
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    const addCloudGuard = screen.getByRole("button", {
      name: "Add Cloud guard",
    });

    // When
    await addCloudGuard.click();

    // Then
    await expect.element(addCloudGuard).toBeDisabled();
    await expect.element(addCloudGuard).toHaveTextContent("Adding…");
    await expect
      .element(screen.getByRole("button", { name: "Add Later guard" }))
      .toBeDisabled();
    expect(executeRegistryArtifactAdditionMock).toHaveBeenCalledTimes(1);
  });

  it("requires confirmation before Remove and commits only after confirmation", async () => {
    // Given
    removeRegistryArtifactMock.mockResolvedValue({
      status: "confirmed",
      tenantArtifacts: [
        { normalizedName: "saved-artifact", versionSpec: "1.0.0" },
      ],
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();

    // When
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Remove", exact: true }))
      .toBeVisible();
    expect(removeRegistryArtifactMock).not.toHaveBeenCalled();

    // When
    await screen.getByRole("button", { name: "Cancel" }).click();

    // Then
    expect(removeRegistryArtifactMock).not.toHaveBeenCalled();

    // When
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();
    await screen.getByRole("button", { name: "Remove", exact: true }).click();

    // Then
    await expect
      .poll(() => removeRegistryArtifactMock.mock.calls)
      .toEqual([["aws-guard"]]);
    await expect
      .poll(() => document.body.textContent)
      .toContain("Artifact removed");
  });

  it("moves focus into Remove confirmation and returns it to the invoking card button", async () => {
    // Given: the tenant-only artifact carries its own card Remove action
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    const removeButton = screen.getByRole("button", {
      name: "Remove saved-artifact",
    });

    // When
    await removeButton.click();

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Cancel" }))
      .toHaveFocus();

    // When
    await userEvent.keyboard("{Escape}");

    // Then
    await expect.element(removeButton).toHaveFocus();
  });

  it("disables duplicate Remove submission while confirmation is pending", async () => {
    // Given
    removeRegistryArtifactMock.mockReturnValue(new Promise(() => {}));
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();

    // When
    await screen.getByRole("button", { name: "Remove", exact: true }).click();

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Removing…" }))
      .toBeDisabled();
    expect(removeRegistryArtifactMock).toHaveBeenCalledTimes(1);
  });

  it("shows an in-use Remove error only inside the dialog with recovery actions", async () => {
    // Given
    let resolveRemoval!: (result: RegistryArtifactRemovalResult) => void;
    removeRegistryArtifactMock.mockReturnValue(
      new Promise<RegistryArtifactRemovalResult>((resolve) => {
        resolveRemoval = resolve;
      }),
    );
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();

    // When
    await screen.getByRole("button", { name: "Remove", exact: true }).click();
    await expect
      .element(screen.getByRole("button", { name: "Removing…" }))
      .toBeDisabled();
    resolveRemoval({ status: "in_use" });

    // Then: the dialog states the rule instead of an error.
    const dialog = screen.getByRole("dialog", {
      name: "AWS guard is in use",
    });
    await expect
      .element(dialog)
      .toHaveTextContent(
        "One or more providers use it. Delete those providers first, then try again.",
      );
    await expect
      .element(dialog.getByRole("alert"))
      .toHaveTextContent(
        "AWS guard is in use. Delete the providers that use it first.",
      );
    await expect
      .element(dialog.getByRole("button", { name: "Remove", exact: true }))
      .not.toBeInTheDocument();
    await expect
      .element(dialog.getByRole("button", { name: "View providers" }))
      .toBeVisible();
    await expect
      .poll(() => dialog.element().contains(document.activeElement))
      .toBe(true);
    expect(cardFor("AWS guard").textContent).toContain("Remove");
    expect(document.body.textContent).not.toContain("Artifact removed");
    expect(document.body.textContent).not.toContain(
      "Existing provider accounts will remain",
    );
  });

  it("treats a running scan as a wait, never as a reason to delete providers", async () => {
    // Given
    removeRegistryArtifactMock
      .mockResolvedValueOnce({ status: "busy" })
      .mockResolvedValueOnce({
        status: "confirmed",
        tenantArtifacts: [],
      });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();

    // When
    await screen.getByRole("button", { name: "Remove", exact: true }).click();

    // Then
    const dialog = screen.getByRole("dialog", { name: "Remove AWS guard?" });
    await expect
      .element(dialog.getByRole("alert"))
      .toHaveTextContent("A scan is using this artifact");
    await expect
      .element(dialog.getByRole("button", { name: "View providers" }))
      .not.toBeInTheDocument();

    // When: the scan finished, so the same dialog can simply try again.
    await dialog.getByRole("button", { name: "Remove", exact: true }).click();

    // Then
    await expect.element(dialog).not.toBeInTheDocument();
    expect(removeRegistryArtifactMock).toHaveBeenCalledTimes(2);
  });

  it("clears the in-use Remove error on close and restores focus before reopening", async () => {
    // Given
    removeRegistryArtifactMock.mockResolvedValue({ status: "in_use" });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    const removeButton = screen.getByRole("button", {
      name: "Remove AWS guard",
    });
    await removeButton.click();
    await screen.getByRole("button", { name: "Remove", exact: true }).click();
    const dialog = screen.getByRole("dialog");
    await expect
      .element(screen.getByRole("dialog", { name: "AWS guard is in use" }))
      .toBeVisible();

    // When: use the footer Close action, not the modal's icon button
    await dialog
      .getByRole("button", { name: "Close", exact: true })
      .first()
      .click();

    // Then
    await expect.element(dialog).not.toBeInTheDocument();
    await expect.element(removeButton).toHaveFocus();
    expect(document.querySelectorAll('[role="alert"]')).toHaveLength(0);

    // When
    await removeButton.click();

    // Then
    await expect.element(dialog.getByRole("alert")).not.toBeInTheDocument();
    await expect
      .element(dialog.getByRole("button", { name: "Remove", exact: true }))
      .toBeEnabled();

    // When
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await screen.getByRole("button", { name: "Remove saved-artifact" }).click();

    // Then
    await expect.element(dialog.getByRole("alert")).not.toBeInTheDocument();
    await expect
      .element(dialog.getByRole("button", { name: "Remove", exact: true }))
      .toBeEnabled();
  });

  it("opens Providers from an in-use Remove error without another deletion", async () => {
    // Given
    removeRegistryArtifactMock.mockResolvedValue({ status: "in_use" });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();
    await screen.getByRole("button", { name: "Remove", exact: true }).click();

    // When
    await screen.getByRole("button", { name: "View providers" }).click();

    // Then
    expect(registryRouter.push).toHaveBeenCalledWith("/providers");
    expect(removeRegistryArtifactMock).toHaveBeenCalledTimes(1);
  });

  it("recovers inside the Remove dialog when the server action rejects", async () => {
    // Given
    removeRegistryArtifactMock.mockRejectedValueOnce(
      new Error("Failed to fetch"),
    );
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();

    // When
    await screen.getByRole("button", { name: "Remove", exact: true }).click();

    // Then
    const dialog = screen.getByRole("dialog", { name: "Remove AWS guard?" });
    await expect
      .element(dialog.getByRole("alert"))
      .toHaveTextContent(
        "The Registry operation could not be completed. Try again.",
      );
    await expect
      .element(dialog.getByRole("button", { name: "Remove", exact: true }))
      .toBeEnabled();
    await expect
      .element(dialog.getByRole("button", { name: "Cancel" }))
      .toBeEnabled();
    expect(document.querySelectorAll('[role="alert"]')).toHaveLength(1);
    expect(document.body.textContent).not.toContain("Artifact removed");
  });

  it("clears a Remove error while retrying and commits only after confirmation", async () => {
    // Given
    let resolveRemoval!: (result: RegistryArtifactRemovalResult) => void;
    removeRegistryArtifactMock
      .mockResolvedValueOnce({ status: "error" })
      .mockReturnValueOnce(
        new Promise<RegistryArtifactRemovalResult>((resolve) => {
          resolveRemoval = resolve;
        }),
      );
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();
    await screen.getByRole("button", { name: "Remove", exact: true }).click();
    const dialog = screen.getByRole("dialog", { name: "Remove AWS guard?" });
    await expect.element(dialog.getByRole("alert")).toBeVisible();
    expect(document.querySelectorAll('[role="alert"]')).toHaveLength(1);

    // When
    await dialog.getByRole("button", { name: "Remove", exact: true }).click();

    // Then
    await expect.element(dialog.getByRole("alert")).not.toBeInTheDocument();
    await expect
      .element(dialog.getByRole("button", { name: "Removing…" }))
      .toBeDisabled();
    expect(cardFor("AWS guard").textContent).toContain("Remove");
    expect(document.body.textContent).not.toContain("Artifact removed");
    expect(removeRegistryArtifactMock).toHaveBeenCalledTimes(2);

    // When
    await userEvent.keyboard("{Escape}");

    // Then
    await expect.element(dialog).toBeVisible();

    // When
    resolveRemoval({
      status: "confirmed",
      tenantArtifacts: [
        { normalizedName: "saved-artifact", versionSpec: "1.0.0" },
      ],
    });

    // Then
    await expect.element(dialog).not.toBeInTheDocument();
    await expect
      .element(screen.getByRole("button", { name: "Remove AWS guard" }))
      .not.toBeInTheDocument();
    await expect
      .poll(() => document.body.textContent)
      .toContain("Artifact removed");
    expect(document.querySelectorAll('[role="alert"]')).toHaveLength(0);
  });

  it("keeps My artifacts visible when a Remove refresh cannot confirm absence", async () => {
    // Given
    removeRegistryArtifactMock.mockResolvedValue({ status: "refresh_failed" });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();

    // When
    await screen.getByRole("button", { name: "Remove", exact: true }).click();

    // Then
    const dialog = screen.getByRole("dialog", { name: "Remove AWS guard?" });
    await expect
      .element(dialog.getByRole("alert"))
      .toHaveTextContent("Registry membership could not be confirmed");
    expect(document.querySelectorAll('[role="alert"]')).toHaveLength(1);
    await expect
      .element(screen.getByRole("button", { name: "Remove", exact: true }))
      .toBeVisible();
  });

  describe("at phone width", () => {
    afterEach(async () => {
      await page.viewport(1280, 800);
    });

    it("pairs the filters, keeps the header actions on the tab row, and never scrolls sideways", async () => {
      // Given
      await page.viewport(390, 844);
      const screen = await render(
        <div
          data-responsive-container
          className="@container"
          style={{ width: 390 }}
        >
          <RegistryExplorer initialState={readyState} />
        </div>,
      );
      const box = (element: Element) => element.getBoundingClientRect();
      const sameRow = (first: Element, second: Element) =>
        box(first).top < box(second).bottom &&
        box(second).top < box(first).bottom;

      // Then
      await expect
        .element(screen.getByRole("combobox", { name: "Sort artifacts" }))
        .toBeVisible();
      const providers = screen
        .getByRole("combobox", { name: "Filter by provider" })
        .element();
      const capabilities = screen
        .getByRole("combobox", { name: "Filter by capability" })
        .element();
      expect(Math.round(box(providers).top)).toBe(
        Math.round(box(capabilities).top),
      );
      expect(
        sameRow(
          screen.getByText("3 artifacts", { exact: true }).element(),
          screen.getByRole("combobox", { name: "Sort artifacts" }).element(),
        ),
      ).toBe(true);
      const tabs = screen.getByRole("tablist").element();
      for (const name of ["Refresh Registry", "Registry API key"]) {
        expect(
          sameRow(tabs, screen.getByRole("button", { name }).element()),
        ).toBe(true);
      }
      await expect
        .element(screen.getByText("API key", { exact: true }))
        .not.toBeVisible();
      expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(390);
    });
  });

  describe("when complete catalog data is unavailable", () => {
    it("keeps incomplete catalog controls and metrics hidden while exposing Retry", async () => {
      // Given / When
      await render(<RegistryExplorer initialState={incompleteState} />);

      // Then
      expect(document.body.textContent).toContain(
        "Registry catalog is incomplete",
      );
      expect(document.body.textContent).toContain("Retry");
      expect(document.body.textContent).not.toContain("Search artifacts");
    });

    it("labels documented unavailability as stale and leaves generic errors generic", async () => {
      // Given / When
      await render(
        <RegistryExplorer initialState={{ status: "unavailable" }} />,
      );

      // Then
      expect(document.body.textContent).toContain("stale or unavailable");

      // Given / When
      await render(<RegistryExplorer initialState={{ status: "error" }} />);

      // Then
      expect(document.body.textContent).toContain("unexpected Registry error");
      expect(document.body.textContent).not.toContain("Reconnect the Registry");
    });
  });
});
