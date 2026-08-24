import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { userEvent } from "vitest/browser";

const {
  addRegistryArtifactMock,
  disconnectRegistryCredentialMock,
  refreshRegistryCollectionsMock,
  removeRegistryArtifactMock,
  submitRegistryCredentialMock,
} = vi.hoisted(() => ({
  addRegistryArtifactMock: vi.fn(),
  disconnectRegistryCredentialMock: vi.fn(),
  refreshRegistryCollectionsMock: vi.fn(),
  removeRegistryArtifactMock: vi.fn(),
  submitRegistryCredentialMock: vi.fn(),
}));

vi.mock("@/actions/registry/registry", () => ({
  addRegistryArtifact: addRegistryArtifactMock,
  disconnectRegistryCredential: disconnectRegistryCredentialMock,
  refreshRegistryCollections: refreshRegistryCollectionsMock,
  removeRegistryArtifact: removeRegistryArtifactMock,
  submitRegistryCredential: submitRegistryCredentialMock,
}));

import { render } from "@/__tests__/render-browser";
import type { RegistryBootstrapState } from "@/types/registry";

import { RegistryExplorer } from "./registry-explorer";

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
        owners: [{ name: "Prowler", type: "organization" }],
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

function AccessInvalidationHarness() {
  const [isAllowed, setIsAllowed] = useState(true);

  return (
    <>
      <button onClick={() => setIsAllowed(false)} type="button">
        Invalidate access
      </button>
      {isAllowed && <RegistryExplorer initialState={readyState} />}
    </>
  );
}

const incompleteState: RegistryBootstrapState = {
  status: "incomplete",
  catalog: { status: "incomplete", reason: "page_failed", collectedCount: 100 },
};

describe("RegistryExplorer", () => {
  beforeEach(() => {
    addRegistryArtifactMock.mockReset();
    disconnectRegistryCredentialMock.mockReset();
    refreshRegistryCollectionsMock.mockReset();
    removeRegistryArtifactMock.mockReset();
    submitRegistryCredentialMock.mockReset();
  });

  describe("when Registry access is not connected", () => {
    it("shows onboarding instead of a catalog", async () => {
      // Given / When
      await render(<RegistryExplorer initialState={onboardingState} />);

      // Then
      expect(document.body.textContent).toContain("Connect Registry");
      expect(document.body.textContent).not.toContain("Available artifacts");
    });

    it("keeps catalog controls unavailable while validation is pending", async () => {
      // Given / When
      await render(
        <RegistryExplorer
          initialState={{ ...onboardingState, status: "validation_pending" }}
        />,
      );

      // Then
      expect(document.body.textContent).toContain(
        "Registry validation in progress",
      );
      expect(document.body.textContent).not.toContain(
        "Search Registry artifacts",
      );
    });
  });

  it("moves focus into the access dialog and returns it to Connect Registry", async () => {
    // Given
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );
    const connectButton = screen.getByRole("button", {
      name: "Connect Registry",
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

  it("announces credential validation while the submitted key stays write-only", async () => {
    // Given
    const key = "registry-test-key";
    submitRegistryCredentialMock.mockReturnValue(new Promise(() => {}));
    const screen = await render(
      <RegistryExplorer initialState={onboardingState} />,
    );

    // When
    await screen.getByRole("button", { name: "Connect Registry" }).click();
    await screen.getByLabelText("Registry key").fill(key);
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then
    await expect
      .element(screen.getByRole("status"))
      .toHaveTextContent("Validating Registry key");
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
    await screen.getByRole("button", { name: "Connect Registry" }).click();
    await screen.getByLabelText("Registry key").fill(key);
    await screen.getByRole("button", { name: "Connect", exact: true }).click();

    // Then
    await expect
      .poll(() => submitRegistryCredentialMock.mock.calls)
      .toEqual([[key]]);
    await expect.element(screen.getByLabelText("Registry key")).toHaveValue("");
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
      .toContain("Available artifacts");
  });

  it("ignores a late mutation result after Registry access invalidates", async () => {
    // Given
    let resolveMutation: ((result: unknown) => void) | undefined;
    addRegistryArtifactMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveMutation = resolve;
        }),
    );
    const screen = await render(<AccessInvalidationHarness />);
    await screen.getByText("Multi-provider").click();
    await screen
      .getByLabelText("Registry explorer")
      .getByText("Cloud guard")
      .click();
    await screen.getByRole("button", { name: "Add" }).click();
    await screen.getByRole("button", { name: "Add artifact" }).click();

    // When
    await screen.getByRole("button", { name: "Invalidate access" }).click();
    resolveMutation?.({
      status: "confirmed",
      tenantArtifacts: [
        ...readyState.tenantArtifacts,
        { normalizedName: "cloud-guard", versionSpec: "latest" },
      ],
    });

    // Then
    await expect
      .poll(() => document.body.textContent)
      .not.toContain("Artifact added");
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
    await screen.getByRole("button", { name: "Replace Registry key" }).click();

    // Then
    await expect
      .poll(() => document.body.textContent)
      .toContain("Existing access is unchanged");
    expect(document.body.textContent).toContain("Available artifacts");
    await expect.element(screen.getByLabelText("Registry key")).toHaveValue("");
    expect(document.body.innerHTML).not.toContain(key);
  });

  describe("when the complete catalog is ready", () => {
    it("keeps Available and authoritative My artifacts distinct", async () => {
      // Given / When
      await render(<RegistryExplorer initialState={readyState} />);

      // Then
      expect(document.body.textContent).toContain("Available artifacts");
      expect(document.body.textContent).toContain("My artifacts");
      expect(document.body.textContent).toContain("Multi-provider");
      expect(document.body.textContent).toContain("Later guard");
      expect(document.body.textContent).toContain("saved-artifact");
      expect(document.body.textContent).toContain("Official artifacts");
    });

    it("derives search from all normalized catalog artifacts", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // When
      await screen.getByLabelText("Search Registry artifacts").fill("later");

      // Then
      await expect
        .poll(() => document.body.textContent)
        .toContain("Later guard");
      await expect
        .poll(() => document.body.textContent)
        .not.toContain("Cloud guard");
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
        "No artifacts match this complete catalog view.",
      );
      await expect
        .element(screen.getByLabelText("Search Registry artifacts"))
        .toBeVisible();
    });

    it("filters complete results by capability", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // When
      await screen.getByText("Provider", { exact: true }).click();

      // Then
      await expect
        .poll(() => document.body.textContent)
        .toContain("Cloud guard");
      await expect
        .poll(() => document.body.textContent)
        .not.toContain("Later guard");
    });

    it("resolves a Multi-provider leaf to one metadata detail", async () => {
      // Given
      const screen = await render(
        <RegistryExplorer initialState={readyState} />,
      );

      // When
      await screen.getByText("Multi-provider").click();
      await expect
        .poll(() => document.body.textContent)
        .toContain("multi-provider artifacts");
      await screen
        .getByLabelText("Registry explorer")
        .getByText("Cloud guard")
        .click();

      // Then
      await expect
        .poll(() => document.body.textContent)
        .toContain("Latest version");
      expect(document.body.textContent).toContain(
        "Registry team (organization)",
      );
      expect(document.body.textContent).not.toContain("Browse versions");
    });
  });

  it("offers Add for an available artifact detail", async () => {
    // Given
    const screen = await render(<RegistryExplorer initialState={readyState} />);

    // When
    await screen.getByText("Multi-provider").click();
    await expect
      .poll(() => document.body.textContent)
      .toContain("multi-provider artifacts");
    await screen
      .getByLabelText("Registry explorer")
      .getByText("Cloud guard")
      .click();

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Add" }))
      .toBeVisible();
  });

  it("announces an Add failure through an alert without animation callbacks", async () => {
    // Given
    addRegistryArtifactMock.mockResolvedValue({ status: "error" });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByText("Multi-provider").click();
    await screen
      .getByLabelText("Registry explorer")
      .getByText("Cloud guard")
      .click();
    await screen.getByRole("button", { name: "Add" }).click();

    // When
    await screen.getByRole("button", { name: "Add artifact" }).click();

    // Then
    await expect
      .element(screen.getByRole("alert"))
      .toHaveTextContent("Registry operation could not be completed");
  });

  it("keeps membership unchanged until an Add is authoritatively confirmed", async () => {
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
    await screen.getByText("Multi-provider").click();
    await screen
      .getByLabelText("Registry explorer")
      .getByText("Cloud guard")
      .click();

    // When
    await screen.getByRole("button", { name: "Add" }).click();

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Add artifact" }))
      .toBeVisible();
    expect(document.body.textContent).not.toContain("Artifact added");

    // When
    await screen.getByRole("button", { name: "Add artifact" }).click();

    // Then
    await expect
      .poll(() => addRegistryArtifactMock.mock.calls)
      .toEqual([[{ normalizedName: "cloud-guard" }]]);
    await expect
      .poll(() => document.body.textContent)
      .toContain("Artifact added");
  });

  it("keeps roots unchanged when an accepted Add cannot be confirmed", async () => {
    // Given
    addRegistryArtifactMock.mockResolvedValue({ status: "refresh_failed" });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByText("Multi-provider").click();
    await screen
      .getByLabelText("Registry explorer")
      .getByText("Cloud guard")
      .click();
    await screen.getByRole("button", { name: "Add" }).click();

    // When
    await screen.getByRole("button", { name: "Add artifact" }).click();

    // Then
    await expect
      .poll(() => document.body.textContent)
      .toContain("Registry membership could not be confirmed");
    await expect
      .element(screen.getByRole("button", { name: "Add artifact" }))
      .toBeVisible();
  });

  it("shows documented Add refusals without moving membership", async () => {
    // Given
    addRegistryArtifactMock.mockResolvedValue({
      status: "refused",
      message: "This version is not verified and cannot be added.",
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByText("Multi-provider").click();
    await screen
      .getByLabelText("Registry explorer")
      .getByText("Cloud guard")
      .click();
    await screen.getByRole("button", { name: "Add" }).click();

    // When
    await screen.getByRole("button", { name: "Add artifact" }).click();

    // Then
    await expect
      .poll(() => document.body.textContent)
      .toContain("This version is not verified and cannot be added.");
    await expect
      .element(screen.getByRole("button", { name: "Add artifact" }))
      .toBeVisible();
  });

  it("disables duplicate Add submission while confirmation is pending", async () => {
    // Given
    addRegistryArtifactMock.mockReturnValue(new Promise(() => {}));
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByText("Multi-provider").click();
    await screen
      .getByLabelText("Registry explorer")
      .getByText("Cloud guard")
      .click();
    await screen.getByRole("button", { name: "Add" }).click();

    // When
    await screen.getByRole("button", { name: "Add artifact" }).click();

    // Then
    await expect
      .element(screen.getByRole("button", { name: "Adding artifact" }))
      .toBeDisabled();
    expect(addRegistryArtifactMock).toHaveBeenCalledTimes(1);
  });

  it("submits a manually entered exact version without version browsing", async () => {
    // Given
    addRegistryArtifactMock.mockResolvedValue({
      status: "confirmed",
      tenantArtifacts: [
        { normalizedName: "aws-guard", versionSpec: "latest" },
        { normalizedName: "saved-artifact", versionSpec: "1.0.0" },
        { normalizedName: "cloud-guard", versionSpec: "2.0.0" },
      ],
    });
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen.getByText("Multi-provider").click();
    await screen
      .getByLabelText("Registry explorer")
      .getByText("Cloud guard")
      .click();
    await screen.getByRole("button", { name: "Add" }).click();

    // When
    await screen.getByLabelText("Use an exact version").click();
    await screen.getByLabelText("Exact version pin").fill(" 2.0.0 ");
    await screen.getByRole("button", { name: "Add artifact" }).click();

    // Then
    await expect
      .poll(() => addRegistryArtifactMock.mock.calls)
      .toEqual([[{ normalizedName: "cloud-guard", versionSpec: "2.0.0" }]]);
    expect(document.body.textContent).not.toContain("Browse versions");
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
    await screen
      .getByLabelText("Registry explorer")
      .getByText("aws-guard")
      .click();

    // When
    await screen.getByRole("button", { name: "Remove" }).click();

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
    await screen.getByRole("button", { name: "Remove" }).click();
    await screen.getByRole("button", { name: "Confirm Remove" }).click();

    // Then
    await expect
      .poll(() => removeRegistryArtifactMock.mock.calls)
      .toEqual([["aws-guard"]]);
    await expect
      .poll(() => document.body.textContent)
      .toContain("Artifact removed");
  });

  it("moves focus into Remove confirmation and returns it to the invoker", async () => {
    // Given
    const screen = await render(<RegistryExplorer initialState={readyState} />);
    await screen
      .getByLabelText("Registry explorer")
      .getByText("aws-guard")
      .click();
    const removeButton = screen.getByRole("button", { name: "Remove" });

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
    await screen
      .getByLabelText("Registry explorer")
      .getByText("aws-guard")
      .click();
    await screen.getByRole("button", { name: "Remove" }).click();

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
    await screen
      .getByLabelText("Registry explorer")
      .getByText("aws-guard")
      .click();
    await screen.getByRole("button", { name: "Remove" }).click();

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
      expect(document.body.textContent).not.toContain(
        "Search Registry artifacts",
      );
      expect(document.body.textContent).not.toContain("Official artifacts");
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
