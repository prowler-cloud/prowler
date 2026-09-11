import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Toaster } from "@/components/shadcn/toast/Toaster";
import { resetToasts } from "@/components/shadcn/toast/use-toast";
import { useProviderWizardStore } from "@/store/provider-wizard/store";

import { ProviderWizardModal } from "./provider-wizard-modal";

const { addRegistryProvider, getInstalledRegistryProviderOptions } = vi.hoisted(
  () => ({
    addRegistryProvider: vi.fn(),
    getInstalledRegistryProviderOptions: vi.fn(),
  }),
);

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));
vi.mock("@/actions/providers/providers", () => ({ addProvider: vi.fn() }));
vi.mock("@/actions/providers/registry-provider", () => ({
  addRegistryProvider,
}));
vi.mock("@/actions/registry/registry", () => ({
  getInstalledRegistryProviderOptions,
}));
vi.mock(
  "@/components/providers/workflow/forms",
  async () => import("../workflow/forms/connect-account-form"),
);
vi.mock("@/hooks/use-scroll-hint", () => ({
  useScrollHint: () => ({ showScrollHint: false }),
}));
vi.mock("@/lib/tours/use-driver-tour", () => ({
  advanceActiveTour: vi.fn(),
  endActiveTour: vi.fn(),
}));
vi.mock("./steps/credentials-step", () => ({
  CredentialsStep: () => <p>Credential details</p>,
}));
vi.mock("./steps/test-connection-step", () => ({
  TestConnectionStep: () => null,
}));
vi.mock("./steps/launch-step", () => ({ LaunchStep: () => null }));
vi.mock("../organizations/azure-org-setup-form", () => ({
  AzureOrgSetupForm: () => null,
}));
vi.mock("../organizations/gcp-org-setup-form", () => ({
  GcpOrgSetupForm: () => null,
}));
vi.mock("../organizations/org-setup-form", () => ({
  OrgSetupForm: () => null,
}));
vi.mock("../organizations/org-account-selection", () => ({
  OrgAccountSelection: () => null,
}));
vi.mock("../organizations/org-launch-scan", () => ({
  OrgLaunchScan: () => null,
}));

const createdAccount = {
  data: {
    id: "account",
    attributes: { provider: "acme", uid: "acme-account", alias: null },
  },
};

async function enterAccountDetails() {
  const user = userEvent.setup();
  render(
    <>
      <ProviderWizardModal open onOpenChange={vi.fn()} />
      <Toaster />
    </>,
  );
  await user.click(
    await screen.findByRole("option", { name: "Acme Cloud Registry" }),
  );
  await user.type(
    screen.getByRole("textbox", { name: "Provider UID" }),
    "acme-account",
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled(),
  );
  return user;
}

describe("provider wizard account creation", () => {
  beforeEach(() => {
    useProviderWizardStore.getState().reset();
    resetToasts();
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "ready",
      options: [{ type: "acme", label: "Acme Cloud" }],
    });
  });

  it("shows progress, blocks repeat clicks, and advances after creation", async () => {
    // Given
    let resolveCreation!: (value: typeof createdAccount) => void;
    addRegistryProvider.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveCreation = resolve;
        }),
    );
    const user = await enterAccountDetails();

    // When
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Then
    const pending = await screen.findByRole("button", {
      name: "Creating provider...",
    });
    expect(pending).toBeDisabled();
    expect(pending).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("button", { name: "Back" })).toBeDisabled();
    await user.dblClick(pending);
    expect(addRegistryProvider).toHaveBeenCalledOnce();

    // When / Then
    await act(async () => resolveCreation(createdAccount));
    expect(await screen.findByText("Credential details")).toBeVisible();
  });

  it("restores Next after a failed creation and retries the same account", async () => {
    // Given
    const failure = { errors: [{ detail: "Creation failed. Try again." }] };
    let resolveCreation!: (value: typeof failure) => void;
    addRegistryProvider
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveCreation = resolve;
          }),
      )
      .mockResolvedValueOnce(createdAccount);
    const user = await enterAccountDetails();

    // When
    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByRole("button", { name: "Creating provider..." });
    await act(async () => resolveCreation(failure));

    // Then
    expect(await screen.findByText(failure.errors[0].detail)).toBeVisible();
    const next = screen.getByRole("button", { name: "Next" });
    await waitFor(() => expect(next).toBeEnabled());
    expect(next).not.toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("button", { name: "Back" })).toBeEnabled();
    expect(screen.getByRole("textbox", { name: "Provider UID" })).toHaveValue(
      "acme-account",
    );

    // When / Then
    await user.click(next);
    expect(await screen.findByText("Credential details")).toBeVisible();
    expect(addRegistryProvider).toHaveBeenCalledTimes(2);
    expect(
      Object.fromEntries(addRegistryProvider.mock.calls[1][0]),
    ).toMatchObject({ providerType: "acme", providerUid: "acme-account" });
  });

  it("shows provider conflicts in the account step and allows retrying", async () => {
    // Given
    const detail =
      "The artifact 'acme' is not installed on this deployment yet. Install it again and retry.";
    addRegistryProvider
      .mockResolvedValueOnce({
        errors: [
          {
            status: "409",
            detail,
            source: { pointer: "/data/attributes/provider" },
          },
        ],
      })
      .mockResolvedValueOnce(createdAccount);
    const user = await enterAccountDetails();

    // When
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Then
    expect(await screen.findByRole("alert")).toHaveTextContent(detail);
    expect(screen.getByRole("textbox", { name: "Provider UID" })).toHaveValue(
      "acme-account",
    );
    const next = screen.getByRole("button", { name: "Next" });
    await waitFor(() => expect(next).toBeEnabled());
    expect(screen.getByRole("button", { name: "Back" })).toBeEnabled();

    // When / Then: the provider becomes available and the same account retries.
    await user.click(next);
    expect(await screen.findByText("Credential details")).toBeVisible();
    expect(screen.queryByText(detail)).not.toBeInTheDocument();
    expect(addRegistryProvider).toHaveBeenCalledTimes(2);
  });

  it("keeps native providers available during a Registry discovery error and retries", async () => {
    // Given
    getInstalledRegistryProviderOptions.mockRejectedValueOnce(
      new Error("Unavailable"),
    );
    const user = userEvent.setup();
    render(<ProviderWizardModal open onOpenChange={vi.fn()} />);
    await screen.findByText("Registry providers could not be loaded");
    expect(
      screen.getByRole("option", { name: /Amazon Web Services/ }),
    ).toBeVisible();

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));
    expect(screen.getByText("No Registry providers available.")).toBeVisible();
    await user.click(
      screen.getByRole("button", { name: "Retry Registry providers" }),
    );

    // Then
    expect(
      await screen.findByRole("option", { name: "Acme Cloud Registry" }),
    ).toBeVisible();
    expect(
      screen.queryByText("Registry providers could not be loaded"),
    ).not.toBeInTheDocument();
  });
});
