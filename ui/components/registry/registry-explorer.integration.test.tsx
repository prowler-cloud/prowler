import { http, HttpResponse } from "msw";
import { useRouter } from "next/navigation";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { userEvent } from "vitest/browser";

import { worker } from "@/__tests__/msw/worker";
import { render } from "@/__tests__/render-browser";
import type { RegistryBootstrapState } from "@/types/registry";

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
    { normalizedName: "saved-artifact", versionSpec: "1.0.0" },
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

function cardFor(name: string) {
  const card = Array.from(document.querySelectorAll("li")).find((item) =>
    item.textContent?.includes(name),
  );
  if (!card) throw new Error(`Expected a rendered card for ${name}`);
  return card;
}

describe("RegistryExplorer", () => {
  it("offers key replacement when the configured Registry rejects access", async () => {
    const screen = await render(
      <RegistryExplorer initialState={{ status: "reconnect" }} />,
    );
    await screen.getByRole("button", { name: "Replace key" }).click();
    await expect.element(screen.getByRole("dialog")).toBeVisible();
    await expect.element(screen.getByLabelText("Registry key")).toBeEnabled();
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
        "A Registry API key is required to install artifacts into this workspace.",
      );
      expect(document.body.textContent).not.toContain(
        "preserved tenant artifact",
      );
      expect(document.body.textContent).toContain("Explore Prowler Registry");
      expect(document.body.textContent).not.toContain("API key connected");
      expect(document.body.textContent).not.toContain("Search artifacts");
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
        "Registry validation in progress",
      );
      await expect
        .element(screen.getByRole("button", { name: "Connect API key" }))
        .toBeEnabled();
      expect(document.body.textContent).not.toContain("Search artifacts");

      // When
      await screen.getByRole("button", { name: "Connect API key" }).click();
      await screen.getByLabelText("Registry key").fill("replacement-key");
      await screen
        .getByRole("button", { name: "Connect", exact: true })
        .click();

      // Then: the replacement POST supersedes the pending validation
      await expect
        .poll(() => submitRegistryCredentialMock.mock.calls)
        .toEqual([["replacement-key"]]);
      await expect
        .poll(() => document.body.textContent)
        .toContain("API key connected");
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
    await expect.element(screen.getByLabelText("Registry key")).toHaveFocus();

    // When
    await userEvent.keyboard("{Escape}");

    // Then
    await expect.element(connectButton).toHaveFocus();
  });

  it("presents the connect dialog with help link and cancel action", async () => {
    // Given
    const screen = await render(
      <RegistryExplorer
        initialState={onboardingState}
        registryKeyUrl="https://registry.private.test/keys"
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
      .toHaveAttribute("href", "https://registry.private.test/keys");

    // When
    await screen.getByRole("button", { name: "Cancel", exact: true }).click();

    // Then
    await expect
      .element(screen.getByLabelText("Registry key"))
      .not.toBeInTheDocument();
  });

  it("preserves the catalog while a watched replacement keeps the form visible and disabled", async () => {
    // Given
    const key = "replacement-key";
    submitRegistryCredentialMock.mockResolvedValue(submittedResult(true));
    trackAndPollTaskMock.mockReturnValue(new Promise(() => {}));
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Manage access" }).click();
    await screen.getByLabelText("Registry key").fill(key);
    await screen.getByRole("button", { name: "Replace key" }).click();

    // Then: the form stays visible; submit shows a disabled Connecting… state
    await expect
      .element(screen.getByRole("button", { name: "Connecting…" }))
      .toBeDisabled();
    await expect.element(screen.getByLabelText("Registry key")).toBeDisabled();
    await expect.element(screen.getByLabelText("Registry key")).toHaveValue("");
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
    await screen.getByLabelText("Registry key").fill("bad-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: the error renders inside the dialog, below the input
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    await expect
      .poll(() => dialog!.querySelector('[role="alert"]')?.textContent)
      .toContain("This Registry key is invalid. Check it and try again.");
    const input = screen.getByLabelText("Registry key").element();
    const alert = dialog!.querySelector('[role="alert"]');
    expect(
      input.compareDocumentPosition(alert!) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();

    // Then: the form is re-enabled for a retry with the key cleared
    await expect
      .element(screen.getByRole("button", { name: "Connect", exact: true }))
      .toBeEnabled();
    await expect.element(screen.getByLabelText("Registry key")).toBeEnabled();
    await expect.element(screen.getByLabelText("Registry key")).toHaveValue("");
    await expect.element(screen.getByLabelText("Registry key")).toHaveFocus();

    // When: a retry submits a fresh key through the same form
    await screen.getByLabelText("Registry key").fill("second-key");
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
    await screen.getByLabelText("Registry key").fill("registry-test-key");
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
    await expect.element(screen.getByLabelText("Registry key")).toBeEnabled();
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
    await screen.getByLabelText("Registry key").fill("stuck-key");
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
    await expect.element(screen.getByLabelText("Registry key")).toBeEnabled();
    expect(document.body.textContent).toContain(
      "Registry validation in progress",
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
    await screen.getByLabelText("Registry key").fill("registry-test-key");
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
    await expect.element(screen.getByLabelText("Registry key")).toBeEnabled();
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
    await screen.getByLabelText("Registry key").fill("registry-test-key");
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
    await screen.getByLabelText("Registry key").fill("slow-key");
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
      "Registry validation in progress",
    );
  });

  it("resets a write-only key before loading authoritative collections", async () => {
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
    await screen.getByLabelText("Registry key").fill(key);
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: repeat submission is disabled and the key has left the form.
    await expect
      .element(screen.getByRole("button", { name: "Connecting…", exact: true }))
      .toBeDisabled();
    await expect
      .poll(() => submitRegistryCredentialMock.mock.calls)
      .toEqual([[key]]);
    await expect.element(screen.getByLabelText("Registry key")).toHaveValue("");
    expect(document.body.innerHTML).not.toContain(key);
    expect(window.location.href).not.toContain(key);
    expect(localStorage.getItem("registry-key")).toBeNull();
    expect(sessionStorage.getItem("registry-key")).toBeNull();

    // When: the accepted task settles through the watcher
    resolveSubmission?.(submittedResult());

    // Then: the explorer lands in ready state and announces the connection
    await expect
      .poll(() => document.body.textContent)
      .toContain("API key connected");
    await expect
      .element(screen.getByRole("tab", { name: /Explore/ }))
      .toBeVisible();
    await expect
      .element(screen.getByLabelText("Registry key"))
      .not.toBeInTheDocument();
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
      await screen.getByRole("button", { name: "Confirm Remove" }).click();

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
      await screen.getByLabelText("Registry key").fill("registry-test-key");

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
      await screen.getByRole("button", { name: "Manage access" }).click();

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
      await screen.getByLabelText("Registry key").fill("registry-test-key");

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
    await screen.getByRole("button", { name: "Manage access" }).click();
    await screen.getByLabelText("Registry key").fill(key);
    await screen.getByRole("button", { name: "Replace key" }).click();

    // Then
    await expect
      .element(screen.getByRole("dialog"))
      .toHaveTextContent("Existing access is unchanged");
    expect(document.body.textContent).toContain("Cloud guard");
    expect(document.body.textContent).toContain("API key connected");
    await expect.element(screen.getByLabelText("Registry key")).toHaveValue("");
    expect(document.body.innerHTML).not.toContain(key);
  });

  it("returns to the credential banner after disconnecting Registry access", async () => {
    // Given
    disconnectRegistryCredentialMock.mockResolvedValue({
      status: "disconnected",
      credential: onboardingState.credential,
      tenantArtifacts: readyState.tenantArtifacts,
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Manage access" }).click();
    await screen.getByRole("button", { name: "Disconnect" }).click();

    // Then
    await expect
      .poll(() => document.body.textContent)
      .toContain("Connect your Registry API key");
    expect(document.body.textContent).toContain(
      "Your 2 preserved tenant artifacts will remain available in My artifacts.",
    );
    expect(document.body.textContent).not.toContain("API key connected");
  });

  describe("when the complete catalog is ready", () => {
    it.each([
      { isBuiltin: true, hasProvider: true },
      { isBuiltin: false, hasProvider: false },
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
      await expect
        .element(screen.getByRole("status", { name: "Built in" }))
        .toBeVisible();
      expect(document.body.textContent).toContain("Added");
      const removeButton = screen.getByRole("button", {
        name: "Remove AWS guard",
      });
      await expect.element(removeButton).toBeVisible();

      // When
      await removeButton.click();
      await screen.getByRole("button", { name: "Confirm Remove" }).click();

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

      // When
      await screen.getByRole("tab", { name: /My artifacts/ }).click();

      // Then
      await expect
        .poll(() => document.body.textContent)
        .toContain("saved-artifact");
      expect(document.body.textContent).toContain("1.0.0");
      expect(document.body.textContent).not.toContain("Later guard");

      // When
      await screen.getByRole("tab", { name: /Explore/ }).click();

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

    it("counts logos and pills together toward the four-item cap and overflow", async () => {
      // Given: six providers alternating known logos and dynamic pills
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
          "custom-scan",
          "gcp",
          "local_thing",
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

      // Then: the cap keeps the first four items of BOTH kinds, so only the
      // first two pills are visible and two items collapse into "+2".
      const blendedCard = cardFor("Blended guard");
      expect(blendedCard.textContent).toContain("6 providers");
      expect(blendedCard.innerText).toContain("+2");
      await expect
        .element(
          screen.getByRole("listitem").getByText("Template", { exact: true }),
        )
        .toBeVisible();
      await expect
        .element(
          screen
            .getByRole("listitem")
            .getByText("Custom Scan", { exact: true }),
        )
        .toBeVisible();
      await expect
        .element(
          screen
            .getByRole("listitem")
            .getByText("Local Thing", { exact: true }),
        )
        .not.toBeInTheDocument();
      // Even collapsed providers remain named for assistive technology.
      expect(blendedCard.textContent).toContain(
        "Providers: AWS, Template, Azure, Custom Scan, Google Cloud, Local Thing",
      );
    });

    it("recovers the owner image when a fresh URL replaces an expired one", async () => {
      const artifact = {
        ...readyState.catalog.artifacts[0],
        isAdded: false,
        owners: [
          {
            name: "Prowler",
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
        .element(screen.getByText("P", { exact: true }))
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
      expect(document.body.textContent).toContain("Prowler");
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
      .element(screen.getByRole("button", { name: "Confirm Remove" }))
      .toBeVisible();
    expect(removeRegistryArtifactMock).not.toHaveBeenCalled();

    // When
    await screen.getByRole("button", { name: "Cancel" }).click();

    // Then
    expect(removeRegistryArtifactMock).not.toHaveBeenCalled();

    // When
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();
    await screen.getByRole("button", { name: "Confirm Remove" }).click();

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
    await screen.getByRole("button", { name: "Confirm Remove" }).click();

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Removing artifact" }))
      .toBeDisabled();
    expect(removeRegistryArtifactMock).toHaveBeenCalledTimes(1);
  });

  it("keeps My artifacts visible when a Remove refresh cannot confirm absence", async () => {
    // Given
    removeRegistryArtifactMock.mockResolvedValue({ status: "refresh_failed" });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByRole("tab", { name: /My artifacts/ }).click();
    await screen.getByRole("button", { name: "Remove AWS guard" }).click();

    // When
    await screen.getByRole("button", { name: "Confirm Remove" }).click();

    // Then
    await expect
      .poll(() => document.body.textContent)
      .toContain("Registry membership could not be confirmed");
    await expect
      .element(screen.getByRole("button", { name: "Confirm Remove" }))
      .toBeVisible();
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
      expect(document.body.textContent).not.toContain("API key connected");
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
      expect(document.body.textContent).not.toContain("Reconnect Registry");
    });
  });
});
