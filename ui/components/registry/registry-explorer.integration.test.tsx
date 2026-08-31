import { useRouter } from "next/navigation";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { userEvent } from "vitest/browser";

import { render } from "@/__tests__/render-browser";
import type { RegistryBootstrapState } from "@/types/registry";

import { RegistryExplorer } from "./registry-explorer";

const {
  builtInOnAddCallbacks,
  disconnectRegistryCredentialMock,
  executeRegistryArtifactAdditionMock,
  refreshRegistryCollectionsMock,
  refreshRegistryCredentialMock,
  removeRegistryArtifactMock,
  submitRegistryCredentialMock,
  trackAndPollTaskMock,
} = vi.hoisted(() => ({
  builtInOnAddCallbacks: [] as Array<() => void>,
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
  refreshRegistryCollections: refreshRegistryCollectionsMock,
  refreshRegistryCredential: refreshRegistryCredentialMock,
  removeRegistryArtifact: removeRegistryArtifactMock,
  submitRegistryCredential: submitRegistryCredentialMock,
}));

// The credential flow watches its validation task through the house task
// watcher; integration tests drive settlement through this mock the same way
// `lib/jira-dispatch-execution.test.ts` does.
vi.mock("@/lib/registry-artifact-execution", () => ({
  executeRegistryArtifactAddition: executeRegistryArtifactAdditionMock,
}));

vi.mock("./registry-artifact-card", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("./registry-artifact-card")>();
  return {
    ...actual,
    RegistryArtifactCard: (
      props: Parameters<typeof actual.RegistryArtifactCard>[0],
    ) => {
      if (props.artifact.isBuiltin) builtInOnAddCallbacks.push(props.onAdd);
      return <actual.RegistryArtifactCard {...props} />;
    },
  };
});

vi.mock("@/store/task-watcher/store", () => ({
  TASK_WATCHER_STATUS: { PENDING: "pending", READY: "ready", ERROR: "error" },
  trackAndPollTask: trackAndPollTaskMock,
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
        hasProvider: false,
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
  beforeEach(() => {
    builtInOnAddCallbacks.length = 0;
    disconnectRegistryCredentialMock.mockReset();
    executeRegistryArtifactAdditionMock.mockReset();
    refreshRegistryCollectionsMock.mockReset();
    refreshRegistryCredentialMock.mockReset();
    removeRegistryArtifactMock.mockReset();
    submitRegistryCredentialMock.mockReset();
    trackAndPollTaskMock.mockReset();
    trackAndPollTaskMock.mockResolvedValue({ status: "ready" });
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

    it("keeps catalog controls unavailable while validation is pending without locking out the connect action", async () => {
      // Given / When
      const screen = await render(
        <RegistryExplorer initialState={validationPendingState} />,
      );

      // Then
      expect(document.body.textContent).toContain(
        "Registry validation in progress",
      );
      await expect
        .element(screen.getByRole("button", { name: "Connect API key" }))
        .toBeEnabled();
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
      <RegistryExplorer initialState={onboardingState} />,
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
      .toBeVisible();

    // When
    await screen.getByRole("button", { name: "Cancel", exact: true }).click();

    // Then
    await expect
      .element(screen.getByLabelText("Registry key"))
      .not.toBeInTheDocument();
  });

  it("shows credential failures inside the open access dialog", async () => {
    // Given
    submitRegistryCredentialMock.mockResolvedValue({
      status: "replacement_failed",
      credential: onboardingState.credential,
    });
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await screen.getByLabelText("Registry key").fill("rejected-key");
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    await expect
      .poll(() => dialog!.textContent)
      .toContain(
        "Registry key validation failed. Existing access is unchanged.",
      );
  });

  it("keeps every dialog control inside the dialog bounds", async () => {
    // Given
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Manage access" }).click();

    // Then
    await expect.element(screen.getByLabelText("Registry key")).toBeVisible();
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    const dialogRect = dialog!.getBoundingClientRect();
    const controls = Array.from(dialog!.querySelectorAll("button, input, a"));
    expect(controls.length).toBeGreaterThan(3);
    for (const control of controls) {
      const rect = control.getBoundingClientRect();
      const name = control.textContent?.trim() || "registry key input";
      expect(rect.right, `${name} overflows right edge`).toBeLessThanOrEqual(
        dialogRect.right + 1,
      );
      expect(rect.left, `${name} overflows left edge`).toBeGreaterThanOrEqual(
        dialogRect.left - 1,
      );
    }
  });

  it("keeps the Connect action visibly separated from the Registry key input", async () => {
    // Given
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();

    // Then
    const inputRect = screen
      .getByLabelText("Registry key")
      .element()
      .getBoundingClientRect();
    const connectRect = screen
      .getByRole("button", { name: "Connect", exact: true })
      .element()
      .getBoundingClientRect();
    const visibleGap = connectRect.top - inputRect.bottom;

    expect(visibleGap).toBeGreaterThanOrEqual(15);
  });

  it("keeps Manage access actions separated from the Registry key input without overlapping", async () => {
    // Given
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Manage access" }).click();

    // Then
    const inputRect = screen
      .getByLabelText("Registry key")
      .element()
      .getBoundingClientRect();
    const disconnectRect = screen
      .getByRole("button", { name: "Disconnect" })
      .element()
      .getBoundingClientRect();
    const replaceRect = screen
      .getByRole("button", { name: "Replace key" })
      .element()
      .getBoundingClientRect();
    const earliestActionTop = Math.min(disconnectRect.top, replaceRect.top);
    const visibleGap = earliestActionTop - inputRect.bottom;
    const actionsOverlap =
      disconnectRect.left < replaceRect.right &&
      disconnectRect.right > replaceRect.left &&
      disconnectRect.top < replaceRect.bottom &&
      disconnectRect.bottom > replaceRect.top;

    expect(visibleGap).toBeGreaterThanOrEqual(15);
    expect(actionsOverlap).toBe(false);
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

  it("shows a disabled Connecting control while the submitted key stays write-only", async () => {
    // Given
    const key = "registry-test-key";
    submitRegistryCredentialMock.mockResolvedValue(submittedResult());
    trackAndPollTaskMock.mockReturnValue(new Promise(() => {}));
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await screen.getByLabelText("Registry key").fill(key);
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then: the form stays visible while the watcher owns the wait
    await expect
      .element(screen.getByRole("button", { name: "Connecting…" }))
      .toBeDisabled();
    await expect.element(screen.getByLabelText("Registry key")).toBeDisabled();
    await expect.element(screen.getByLabelText("Registry key")).toHaveValue("");
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
      .toContain("Registry key validation could not be completed. Try again.");
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

    // Then: while the submission is in flight the key exists nowhere
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
      .poll(() => document.body.textContent)
      .toContain("Registry connected");
    await expect
      .element(screen.getByLabelText("Registry key"))
      .not.toBeInTheDocument();
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
      .poll(() => document.body.textContent)
      .toContain("Existing access is unchanged");
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
    it("shows the connected header, tab counts, and the full catalog grid", async () => {
      // Given / When
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // Then
      expect(document.body.textContent).toContain("API key connected");
      await expect
        .element(screen.getByRole("tab", { name: /Explore/ }))
        .toHaveTextContent("3");
      await expect
        .element(screen.getByRole("tab", { name: /My artifacts/ }))
        .toHaveTextContent("2");
      expect(document.body.textContent).toContain("3 artifacts");
      expect(document.body.textContent).toContain("AWS guard");
      expect(document.body.textContent).toContain("Later guard");
      expect(document.body.textContent).toContain("Cloud guard");
      expect(document.body.textContent).toContain("v3.0.0");
      expect(document.body.textContent).toContain("42");
    });

    it("marks already-added artifacts with Remove instead of Add", async () => {
      // Given / When
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // Then
      expect(document.body.textContent).toContain("Added");
      await expect
        .element(screen.getByRole("button", { name: "Add Cloud guard" }))
        .toBeVisible();
      await expect
        .element(screen.getByRole("button", { name: "Remove AWS guard" }))
        .toBeVisible();
      expect(
        screen.container.ownerDocument.querySelector(
          '[aria-label="Add AWS guard"]',
        ),
      ).toBeNull();
    });

    it("shows built-ins as non-installable even when their add callback is forced", async () => {
      // Given
      const builtInState: RegistryBootstrapState = {
        ...readyState,
        catalog: {
          ...readyState.catalog,
          artifacts: [
            {
              ...readyState.catalog.artifacts[2],
              normalizedName: "built-in-guard",
              name: "Built in guard",
              isBuiltin: true,
            },
          ],
        },
        tenantArtifacts: [],
      };
      const screen = await render(
        <RegistryExplorer initialState={builtInState} />,
      );

      // Then
      await expect
        .element(screen.getByRole("status", { name: "Built in" }))
        .toBeVisible();
      expect(
        screen.container.ownerDocument.querySelector(
          '[aria-label="Add Built in guard"]',
        ),
      ).toBeNull();
      const onAdd = builtInOnAddCallbacks.at(-1);
      if (!onAdd) throw new Error("expected the built-in card callback");

      // When
      await onAdd();

      // Then
      expect(executeRegistryArtifactAdditionMock).not.toHaveBeenCalled();
      expect(document.body.textContent).not.toContain("Adding…");
      expect(document.body.textContent).not.toContain("Artifact added");
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

      // Then: options stay selectable by their plain accessible names
      await expect
        .element(screen.getByRole("option", { name: "All providers" }))
        .toBeVisible();

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

    it("filters complete results by capability chips with pressed state", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );
      const allChip = screen.getByRole("button", { name: "All", exact: true });
      const providersChip = screen.getByRole("button", {
        name: "Providers",
        exact: true,
      });

      // Then
      await expect.element(allChip).toHaveAttribute("aria-pressed", "true");

      // When
      await providersChip.click();

      // Then
      await expect
        .element(providersChip)
        .toHaveAttribute("aria-pressed", "true");
      await expect.element(allChip).toHaveAttribute("aria-pressed", "false");
      await expect
        .poll(() => document.body.textContent)
        .toContain("Cloud guard");
      await expect
        .poll(() => document.body.textContent)
        .not.toContain("Later guard");

      // When
      await allChip.click();

      // Then
      await expect.element(allChip).toHaveAttribute("aria-pressed", "true");
      await expect
        .poll(() => document.body.textContent)
        .toContain("Later guard");
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

    it("shows the first owner with its logo on the card", async () => {
      // Given / When
      await render(<RegistryExplorer initialState={readyState} />);

      // Then
      const awsCard = cardFor("AWS guard");
      expect(awsCard.textContent).toContain("Prowler");
      const logo = awsCard.querySelector("img");
      expect(logo?.getAttribute("src")).toBe(
        "https://cdn.example/prowler-logo.png",
      );
    });

    it("falls back to an initial-letter owner avatar without a logo", async () => {
      // Given / When
      await render(<RegistryExplorer initialState={readyState} />);

      // Then
      const cloudCard = cardFor("Cloud guard");
      expect(cloudCard.textContent).toContain("Registry team");
      expect(cloudCard.querySelector("img")).toBeNull();
      const hiddenSpans = Array.from(
        cloudCard.querySelectorAll('span[aria-hidden="true"]'),
      ).map((span) => span.textContent?.trim());
      expect(hiddenSpans).toContain("R");
    });

    it("hides the whole owner row when the artifact has no owners", async () => {
      // Given / When
      await render(<RegistryExplorer initialState={readyState} />);

      // Then
      const laterCard = cardFor("Later guard");
      expect(laterCard.querySelector("img")).toBeNull();
      const hiddenLetters = Array.from(
        laterCard.querySelectorAll('span[aria-hidden="true"]'),
      ).filter((span) => /^[A-Za-z]$/.test(span.textContent?.trim() ?? ""));
      expect(hiddenLetters).toEqual([]);
    });

    it("keeps card accessible names intact without monogram initials", async () => {
      // Given / When
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // Then: cards keep their name-based content and action locators
      expect(document.body.textContent).toContain("Later guard");
      await expect
        .element(screen.getByRole("button", { name: "Add Cloud guard" }))
        .toBeVisible();
      // The logo slot no longer leaks provider-derived initials ("az" for the
      // azure artifact) into the page text.
      expect(document.body.textContent).not.toContain("az");
    });

    it("shows a neutral package mark instead of a provider logo in the header", async () => {
      // Given / When
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // Then: the first aria-hidden icon slot of the marketplace card holds
      // the neutral package mark, not a provider logo.
      const awsHeaderIcon = cardFor("AWS guard").querySelector(
        'span[aria-hidden="true"] > svg',
      );
      expect(awsHeaderIcon?.getAttribute("class")).toContain("lucide-package");

      // When: tenant-only cards render in My artifacts
      await screen.getByRole("tab", { name: /My artifacts/ }).click();

      // Then
      const tenantHeaderIcon = cardFor("saved-artifact").querySelector(
        'span[aria-hidden="true"] > svg',
      );
      expect(tenantHeaderIcon?.getAttribute("class")).toContain(
        "lucide-package",
      );
    });

    it("names the single provider accessibly beside its footer logo", async () => {
      // Given / When
      await render(<RegistryExplorer initialState={readyState} />);

      // Then: one provider renders only its logo plus an accessible name,
      // never a "1 providers" count.
      const awsCard = cardFor("AWS guard");
      expect(awsCard.textContent).toContain("Provider: AWS");
      expect(awsCard.textContent).not.toContain("1 providers");
    });

    it("shows a provider count with accessible names for multi-provider artifacts", async () => {
      // Given / When
      await render(<RegistryExplorer initialState={readyState} />);

      // Then
      const cloudCard = cardFor("Cloud guard");
      expect(cloudCard.textContent).toContain("2 providers");
      expect(cloudCard.textContent).toContain("Providers: AWS, Google Cloud");
    });

    it("collapses provider logos past four into an overflow badge", async () => {
      // Given
      const wideArtifact = {
        normalizedName: "wide-guard",
        name: "Wide guard",
        description: "Artifact spanning many providers",
        latestVersion: "1.0.0",
        providers: ["aws", "azure", "gcp", "kubernetes", "m365", "github"],
        isVerified: false,
        isOfficial: false,
        isBuiltin: false,
        isMeta: true,
        hasProvider: true,
        hasChecks: true,
        hasCompliance: false,
        versionCount: 1,
        totalDownloads: 7,
        owners: [],
      };

      // When
      await render(
        <RegistryExplorer
          initialState={{
            ...readyState,
            catalog: { status: "complete", artifacts: [wideArtifact] },
            tenantArtifacts: [],
          }}
        />,
      );

      // Then: count, capped logo row, overflow badge, and full accessible list
      const wideCard = cardFor("Wide guard");
      expect(wideCard.textContent).toContain("6 providers");
      expect(wideCard.textContent).toContain(
        "Providers: AWS, Azure, Google Cloud, Kubernetes, Microsoft 365, GitHub",
      );
      const overflowBadge = Array.from(wideCard.querySelectorAll("span")).find(
        (span) => span.textContent === "+2",
      );
      expect(overflowBadge).toBeDefined();
      expect(overflowBadge?.previousElementSibling?.childElementCount).toBe(4);
    });

    it("renders a text pill for a provider without a bespoke badge beside known logos", async () => {
      // Given: one known provider (logo) plus one dynamic provider (pill)
      const mixedArtifact = {
        normalizedName: "mixed-guard",
        name: "Mixed guard",
        description: "Artifact mixing known and dynamic providers",
        latestVersion: "1.0.0",
        providers: ["aws", "template"],
        isVerified: false,
        isOfficial: false,
        isBuiltin: false,
        isMeta: false,
        hasProvider: true,
        hasChecks: true,
        hasCompliance: false,
        versionCount: 1,
        totalDownloads: 5,
        owners: [],
      };

      // When
      await render(
        <RegistryExplorer
          initialState={{
            ...readyState,
            catalog: { status: "complete", artifacts: [mixedArtifact] },
            tenantArtifacts: [],
          }}
        />,
      );

      // Then: the dynamic provider renders a visible-text pill, the known
      // provider keeps its logo, and the sr-only carrier names both.
      const mixedCard = cardFor("Mixed guard");
      const pills = Array.from(
        mixedCard.querySelectorAll('span[data-slot="badge"]'),
      );
      expect(pills.map((pill) => pill.textContent)).toEqual(["Template"]);
      expect(mixedCard.textContent).toContain("Providers: AWS, Template");
      // The visible cluster row holds exactly the logo + the pill.
      expect(pills[0]?.parentElement?.childElementCount).toBe(2);
    });

    it("renders only text pills when no provider has a bespoke badge", async () => {
      // Given: every provider is dynamic
      const dynamicArtifact = {
        normalizedName: "dynamic-guard",
        name: "Dynamic guard",
        description: "Artifact with only dynamic providers",
        latestVersion: "1.0.0",
        providers: ["template", "custom-scan"],
        isVerified: false,
        isOfficial: false,
        isBuiltin: false,
        isMeta: false,
        hasProvider: true,
        hasChecks: true,
        hasCompliance: false,
        versionCount: 1,
        totalDownloads: 2,
        owners: [],
      };

      // When
      await render(
        <RegistryExplorer
          initialState={{
            ...readyState,
            catalog: { status: "complete", artifacts: [dynamicArtifact] },
            tenantArtifacts: [],
          }}
        />,
      );

      // Then: both providers render as name pills and no icon glyph remains
      // in the visible cluster row.
      const dynamicCard = cardFor("Dynamic guard");
      const pills = Array.from(
        dynamicCard.querySelectorAll('span[data-slot="badge"]'),
      );
      expect(pills.map((pill) => pill.textContent)).toEqual([
        "Template",
        "Custom Scan",
      ]);
      const clusterRow = pills[0]?.parentElement;
      expect(clusterRow?.childElementCount).toBe(2);
      expect(clusterRow?.querySelector("svg")).toBeNull();
    });

    it("counts logos and pills together toward the four-item cap and overflow", async () => {
      // Given: six providers alternating known logos and dynamic pills
      const blendedArtifact = {
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
        isVerified: false,
        isOfficial: false,
        isBuiltin: false,
        isMeta: true,
        hasProvider: true,
        hasChecks: true,
        hasCompliance: false,
        versionCount: 1,
        totalDownloads: 9,
        owners: [],
      };

      // When
      await render(
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
      const pills = Array.from(
        blendedCard.querySelectorAll('span[data-slot="badge"]'),
      );
      expect(pills.map((pill) => pill.textContent)).toEqual([
        "Template",
        "Custom Scan",
      ]);
      expect(pills[0]?.parentElement?.childElementCount).toBe(4);
      const overflowBadge = Array.from(
        blendedCard.querySelectorAll("span"),
      ).find((span) => span.textContent === "+2");
      expect(overflowBadge).toBeDefined();
    });

    it("falls back to the initial-letter avatar when the owner logo fails to load", async () => {
      // Given
      await render(<RegistryExplorer initialState={readyState} />);
      const logo = cardFor("AWS guard").querySelector("img");
      expect(logo).not.toBeNull();

      // When: the short-lived signed URL expires and the image errors out
      logo?.dispatchEvent(new Event("error"));

      // Then: the logo is replaced by the initial-letter avatar and the
      // owner name stays visible.
      await expect
        .poll(() => cardFor("AWS guard").querySelector("img"))
        .toBeNull();
      const hiddenSpans = Array.from(
        cardFor("AWS guard").querySelectorAll('span[aria-hidden="true"]'),
      ).map((span) => span.textContent?.trim());
      expect(hiddenSpans).toContain("P");
      expect(cardFor("AWS guard").textContent).toContain("Prowler");
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
    await expect
      .poll(() => document.body.textContent)
      .toContain("Artifact added");
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

  it("disables only the pending card while an Add confirmation is pending", async () => {
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
      .toBeEnabled();
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
