import { useRouter } from "next/navigation";
import type { ReactElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { userEvent } from "vitest/browser";

import { render as renderBrowser } from "@/__tests__/render-browser";
import type { RegistryBootstrapState } from "@/types/registry";

import { RegistryAccessBoundary } from "./registry-access-boundary";
import { RegistryEligibilityProvider } from "./registry-eligibility-provider";
import { RegistryExplorer } from "./registry-explorer";

const {
  addRegistryArtifactMock,
  disconnectRegistryCredentialMock,
  refreshRegistryCollectionsMock,
  refreshRegistryEligibilityMock,
  removeRegistryArtifactMock,
  submitRegistryCredentialMock,
} = vi.hoisted(() => ({
  addRegistryArtifactMock: vi.fn(),
  disconnectRegistryCredentialMock: vi.fn(),
  refreshRegistryCollectionsMock: vi.fn(),
  refreshRegistryEligibilityMock: vi.fn(),
  removeRegistryArtifactMock: vi.fn(),
  submitRegistryCredentialMock: vi.fn(),
}));

vi.mock("@/actions/registry/registry", () => ({
  addRegistryArtifact: addRegistryArtifactMock,
  disconnectRegistryCredential: disconnectRegistryCredentialMock,
  refreshRegistryCollections: refreshRegistryCollectionsMock,
  refreshRegistryEligibility: refreshRegistryEligibilityMock,
  removeRegistryArtifact: removeRegistryArtifactMock,
  submitRegistryCredential: submitRegistryCredentialMock,
}));

const render = (
  ui: ReactElement,
  options?: Parameters<typeof renderBrowser>[1],
) =>
  renderBrowser(
    <RegistryEligibilityProvider>{ui}</RegistryEligibilityProvider>,
    options,
  );

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

let registryRouter: ReturnType<typeof useRouter>;

function AuthorizedRegistryExplorer({
  initialState = readyState,
}: {
  initialState?: RegistryBootstrapState;
}) {
  registryRouter = useRouter();

  return (
    <RegistryAccessBoundary initialLeaseDurationMs={30_000}>
      <RegistryExplorer initialState={initialState} />
    </RegistryAccessBoundary>
  );
}

async function expectRegistryAccessRevoked(
  screen: Awaited<ReturnType<typeof render>>,
) {
  // The subtitle renders in both the ready and onboarding explorer states, so
  // its absence proves the explorer actually unmounted on revocation.
  await expect
    .element(
      screen.getByText(
        "Discover and install checks, compliance frameworks, and providers for your workspace.",
      ),
    )
    .not.toBeInTheDocument();
  await expect
    .poll(() => registryRouter.replace)
    .toHaveBeenCalledWith("/profile");
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
    addRegistryArtifactMock.mockReset();
    disconnectRegistryCredentialMock.mockReset();
    refreshRegistryCollectionsMock.mockReset();
    refreshRegistryEligibilityMock.mockReset();
    removeRegistryArtifactMock.mockReset();
    submitRegistryCredentialMock.mockReset();
    refreshRegistryEligibilityMock.mockResolvedValue({
      status: "eligible",
      leaseDurationMs: 30_000,
    });
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

    it("keeps catalog controls unavailable while validation is pending", async () => {
      // Given / When
      const screen = await render(
        <RegistryExplorer
          initialState={{ ...onboardingState, status: "validation_pending" }}
        />,
      );

      // Then
      expect(document.body.textContent).toContain(
        "Registry validation in progress",
      );
      await expect
        .element(screen.getByRole("button", { name: "Connect API key" }))
        .toBeDisabled();
      expect(document.body.textContent).not.toContain("Search artifacts");
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

  it("preserves the catalog while replacement validation hides credential controls", async () => {
    // Given
    const key = "replacement-key";
    submitRegistryCredentialMock.mockReturnValue(new Promise(() => {}));
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByRole("button", { name: "Manage access" }).click();
    await screen.getByLabelText("Registry key").fill(key);
    await screen.getByRole("button", { name: "Replace key" }).click();

    // Then
    await expect
      .element(screen.getByRole("status"))
      .toHaveTextContent("Validating your Registry key");
    await expect
      .element(screen.getByLabelText("Registry key"))
      .not.toBeInTheDocument();
    await expect
      .element(screen.getByRole("button", { name: "Disconnect" }))
      .not.toBeInTheDocument();
    await expect
      .element(screen.getByRole("button", { name: "Replace key" }))
      .not.toBeInTheDocument();
    expect(document.body.textContent).toContain("Cloud guard");
    expect(document.body.innerHTML).not.toContain(key);
  });

  it("announces credential validation while the submitted key stays write-only", async () => {
    // Given
    const key = "registry-test-key";
    submitRegistryCredentialMock.mockReturnValue(new Promise(() => {}));
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect API key" }).click();
    await screen.getByLabelText("Registry key").fill(key);
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then
    await expect
      .element(screen.getByRole("status"))
      .toHaveTextContent("Validating your Registry key");
    await expect
      .element(screen.getByLabelText("Registry key"))
      .not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(key);
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

    // Then
    await expect
      .poll(() => submitRegistryCredentialMock.mock.calls)
      .toEqual([[key]]);
    await expect
      .element(screen.getByLabelText("Registry key"))
      .not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(key);
    expect(window.location.href).not.toContain(key);
    expect(localStorage.getItem("registry-key")).toBeNull();
    expect(sessionStorage.getItem("registry-key")).toBeNull();

    // When
    resolveSubmission?.({
      status: "connected",
      credential: readyState.credential,
    });

    // Then
    await expect
      .poll(() => document.body.textContent)
      .toContain("API key connected");
    await expect
      .element(screen.getByRole("tab", { name: /Explore/ }))
      .toBeVisible();
  });

  describe("when a Registry action loses authorization", () => {
    it("fails closed to Profile when unknown eligibility outlives the lease", async () => {
      // Given: the session token is absent, so eligibility can only report unknown
      refreshRegistryEligibilityMock.mockResolvedValue({ status: "unknown" });

      function ShortLeaseRegistryExplorer() {
        registryRouter = useRouter();

        return (
          <RegistryAccessBoundary initialLeaseDurationMs={80}>
            <RegistryExplorer initialState={readyState} />
          </RegistryAccessBoundary>
        );
      }

      // When
      const screen = await render(<ShortLeaseRegistryExplorer />);

      // Then: the lease briefly holds access, then the boundary fails closed
      await expect
        .element(screen.getByRole("tab", { name: /Explore/ }))
        .toBeVisible();
      await expect
        .poll(() => registryRouter.replace)
        .toHaveBeenCalledWith("/profile");
    });

    it("removes Registry and routes to Profile when Add is denied", async () => {
      // Given
      addRegistryArtifactMock.mockResolvedValue({ status: "access_denied" });
      const screen = await render(<AuthorizedRegistryExplorer />);

      // When
      await screen.getByRole("button", { name: "Add Cloud guard" }).click();

      // Then
      await expectRegistryAccessRevoked(screen);
    });

    it("removes Registry and routes to Profile when Remove is denied", async () => {
      // Given
      removeRegistryArtifactMock.mockResolvedValue({ status: "access_denied" });
      const screen = await render(<AuthorizedRegistryExplorer />);
      await screen.getByRole("tab", { name: /My artifacts/ }).click();
      await screen.getByRole("button", { name: "Remove AWS guard" }).click();

      // When
      await screen.getByRole("button", { name: "Confirm Remove" }).click();

      // Then
      await expectRegistryAccessRevoked(screen);
    });

    it("removes Registry and routes to Profile when credential submission is denied", async () => {
      // Given
      submitRegistryCredentialMock.mockResolvedValue({
        status: "access_denied",
      });
      const screen = await render(
        <AuthorizedRegistryExplorer initialState={onboardingState} />,
      );
      await screen.getByRole("button", { name: "Connect API key" }).click();
      await screen.getByLabelText("Registry key").fill("registry-test-key");

      // When
      await screen
        .getByRole("button", { name: "Connect", exact: true })
        .click();

      // Then
      await expectRegistryAccessRevoked(screen);
    });

    it("removes Registry and routes to Profile when disconnect is denied", async () => {
      // Given
      disconnectRegistryCredentialMock.mockResolvedValue({
        status: "access_denied",
      });
      const screen = await render(<AuthorizedRegistryExplorer />);
      await screen.getByRole("button", { name: "Manage access" }).click();

      // When
      await screen.getByRole("button", { name: "Disconnect" }).click();

      // Then
      await expectRegistryAccessRevoked(screen);
    });

    it("removes Registry and routes to Profile when post-connect collection refresh is denied", async () => {
      // Given
      submitRegistryCredentialMock.mockResolvedValue({
        status: "connected",
        credential: readyState.credential,
      });
      refreshRegistryCollectionsMock.mockResolvedValue({
        status: "access_denied",
      });
      const screen = await render(
        <AuthorizedRegistryExplorer initialState={onboardingState} />,
      );
      await screen.getByRole("button", { name: "Connect API key" }).click();
      await screen.getByLabelText("Registry key").fill("registry-test-key");

      // When
      await screen
        .getByRole("button", { name: "Connect", exact: true })
        .click();

      // Then
      await expectRegistryAccessRevoked(screen);
    });
  });

  it("suppresses a late Add confirmation after the real access boundary revokes Registry", async () => {
    // Given
    let resolveMutation: ((result: unknown) => void) | undefined;
    refreshRegistryEligibilityMock
      .mockResolvedValueOnce({ status: "eligible", leaseDurationMs: 30_000 })
      .mockResolvedValueOnce({ status: "ineligible" });
    addRegistryArtifactMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveMutation = resolve;
        }),
    );
    const screen = await render(<AuthorizedRegistryExplorer />);
    await screen.getByRole("button", { name: "Add Cloud guard" }).click();

    // When
    window.dispatchEvent(new Event("focus"));
    await expectRegistryAccessRevoked(screen);
    resolveMutation?.({
      status: "confirmed",
      tenantArtifacts: [
        ...readyState.tenantArtifacts,
        { normalizedName: "cloud-guard", versionSpec: "latest" },
      ],
    });

    // Then
    expect(document.body.textContent).not.toContain("Artifact added");
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
  });

  it("keeps ordinary Add errors local without revoking Registry", async () => {
    // Given
    addRegistryArtifactMock.mockResolvedValue({ status: "error" });
    const screen = await render(<AuthorizedRegistryExplorer />);

    // When
    await screen.getByRole("button", { name: "Add Cloud guard" }).click();

    // Then
    await expect
      .element(screen.getByRole("alert"))
      .toHaveTextContent("Registry operation could not be completed");
    await expect
      .element(screen.getByRole("button", { name: "Add Cloud guard" }))
      .toBeEnabled();
  });

  it("adds the latest version directly from the card once confirmed", async () => {
    // Given
    addRegistryArtifactMock.mockResolvedValue({
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
      .poll(() => addRegistryArtifactMock.mock.calls)
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
    addRegistryArtifactMock.mockResolvedValue({ status: "refresh_failed" });
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

  it("keeps documented Add refusals local without revoking Registry", async () => {
    // Given
    addRegistryArtifactMock.mockResolvedValue({
      status: "refused",
      message: "This version is not verified and cannot be added.",
    });
    const screen = await render(<AuthorizedRegistryExplorer />);

    // When
    await screen.getByRole("button", { name: "Add Cloud guard" }).click();

    // Then
    await expect
      .poll(() => document.body.textContent)
      .toContain("This version is not verified and cannot be added.");
    await expect
      .element(screen.getByRole("button", { name: "Add Cloud guard" }))
      .toBeEnabled();
  });

  it("disables only the pending card while an Add confirmation is pending", async () => {
    // Given
    addRegistryArtifactMock.mockReturnValue(new Promise(() => {}));
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
    expect(addRegistryArtifactMock).toHaveBeenCalledTimes(1);
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
