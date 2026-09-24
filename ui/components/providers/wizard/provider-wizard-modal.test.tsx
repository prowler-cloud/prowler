import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Toaster } from "@/components/shadcn/toast/Toaster";
import { resetToasts } from "@/components/shadcn/toast/use-toast";
import {
  PROVIDER_FUNNEL_EVENT,
  type ProviderFunnelDetail,
} from "@/lib/provider-funnel/provider-funnel-events";
import { endActiveTour } from "@/lib/tours/use-driver-tour";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { useUIStore } from "@/store/ui/store";

import { ProviderWizardModal } from "./provider-wizard-modal";

const {
  addCredentialsProvider,
  addProvider,
  addRegistryProvider,
  getInstalledRegistryProviderOptions,
  testProviderConnection,
  updateCredentialsProvider,
  updateProvider,
} = vi.hoisted(() => ({
  addCredentialsProvider: vi.fn(),
  addProvider: vi.fn(),
  addRegistryProvider: vi.fn(),
  getInstalledRegistryProviderOptions: vi.fn(),
  testProviderConnection: vi.fn(),
  updateCredentialsProvider: vi.fn(),
  updateProvider: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));
vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: { tenantId: "tenant-abc" },
    status: "authenticated",
  }),
}));
vi.mock("@/actions/providers/providers", () => ({
  addCredentialsProvider,
  addProvider,
  updateCredentialsProvider,
  updateProvider,
}));
// The real module reaches next-auth through lib/helper -> auth.config.
vi.mock("@/lib/provider-helpers", () => ({ testProviderConnection }));
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
  CredentialsStep: ({ onBack }: { onBack: () => void }) => (
    <>
      <p>Credential details</p>
      <button type="button" onClick={onBack}>
        Back to provider
      </button>
    </>
  ),
}));
vi.mock("./steps/test-connection-step", () => ({
  TestConnectionStep: ({
    onResetCredentials,
  }: {
    onResetCredentials: () => void;
  }) => (
    <>
      <p>Connection test</p>
      <button type="button" onClick={onResetCredentials}>
        Reset credentials
      </button>
    </>
  ),
}));
vi.mock("./steps/launch-step", () => ({
  LaunchStep: ({ onBack }: { onBack: () => void }) => (
    <>
      <p>Launch scan</p>
      <button type="button" onClick={onBack}>
        Back to form
      </button>
    </>
  ),
}));
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
    // Registry discovery only runs in Cloud.
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    useProviderWizardStore.getState().reset();
    resetToasts();
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "ready",
      options: [{ type: "acme", label: "Acme Cloud" }],
    });
    testProviderConnection.mockResolvedValue({ connected: true, error: null });
    updateCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
    updateProvider.mockResolvedValue({ data: { id: "provider-1" } });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
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

  it("tells the rest of the app the tenant now has a provider", async () => {
    // Given
    useUIStore.setState({ hasProviders: false, hasProvidersResolved: true });
    addRegistryProvider.mockResolvedValueOnce(createdAccount);
    const user = await enterAccountDetails();

    // When
    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("Credential details");

    // Then: the sidebar stops offering Add Provider without waiting for a reload.
    expect(useUIStore.getState().hasProviders).toBe(true);
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
    const next = await screen.findByRole("button", { name: "Next" });
    await waitFor(() => expect(next).toBeEnabled());
    expect(screen.getByRole("button", { name: "Back" })).toBeEnabled();

    // When / Then: the provider becomes available and the same account retries.
    await user.click(next);
    expect(await screen.findByText("Credential details")).toBeVisible();
    expect(screen.queryByText(detail)).not.toBeInTheDocument();
    expect(addRegistryProvider).toHaveBeenCalledTimes(2);
  });

  it("signals the provider type the user picked, once", async () => {
    // Given
    const funnelSignals: ProviderFunnelDetail[] = [];
    const recordFunnelSignal: EventListener = (event) => {
      funnelSignals.push((event as CustomEvent<ProviderFunnelDetail>).detail);
    };
    window.addEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelSignal);
    const user = userEvent.setup();
    render(<ProviderWizardModal open onOpenChange={vi.fn()} />);

    await screen.findByRole("option", { name: "Acme Cloud Registry" });

    // When
    await user.click(
      screen.getByRole("option", { name: /Amazon Web Services/ }),
    );
    await screen.findByRole("radio", { name: /IAM Role/ });
    window.removeEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelSignal);

    // Then
    expect(funnelSignals).toEqual([
      { step: "provider_type_selected", providerType: "aws" },
    ]);
  });

  describe("when the user picks AWS", () => {
    const ROLE_ARN = "arn:aws:iam::123456789012:role/ProwlerScan";

    async function pickAws() {
      const user = userEvent.setup();
      render(<ProviderWizardModal open onOpenChange={vi.fn()} />);
      await screen.findByRole("option", { name: "Acme Cloud Registry" });
      await user.click(
        screen.getByRole("option", { name: /Amazon Web Services/ }),
      );
      await screen.findByRole("textbox", { name: /Role ARN/ });
      return user;
    }

    it("connects the account and its credentials in one step, then tests the connection", async () => {
      // Given
      addProvider.mockResolvedValue({ data: { id: "provider-1" } });
      addCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
      const user = await pickAws();

      // When
      await user.type(
        screen.getByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );
      const connect = screen.getByRole("button", { name: "Connect account" });
      await waitFor(() => expect(connect).toBeEnabled());
      await user.click(connect);

      // Then: neither the credentials step nor the connection test shows up.
      expect(await screen.findByText("Launch scan")).toBeVisible();
      expect(screen.queryByText("Credential details")).not.toBeInTheDocument();
      expect(screen.queryByText("Connection test")).not.toBeInTheDocument();
      expect(testProviderConnection).toHaveBeenCalledWith("provider-1");
      expect(useProviderWizardStore.getState()).toMatchObject({
        providerId: "provider-1",
        secretId: "secret-1",
        via: "role",
      });
    });

    it("keeps the account on the one-step form when the connection is refused", async () => {
      // Given
      addProvider.mockResolvedValue({ data: { id: "provider-1" } });
      addCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
      testProviderConnection.mockResolvedValue({
        connected: false,
        error: "The role could not be assumed.",
      });
      const user = await pickAws();

      // When
      await user.type(
        screen.getByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );
      const connect = screen.getByRole("button", { name: "Connect account" });
      await waitFor(() => expect(connect).toBeEnabled());
      await user.click(connect);

      // Then
      expect(
        await screen.findByText("The role could not be assumed."),
      ).toBeVisible();
      expect(screen.queryByText("Launch scan")).not.toBeInTheDocument();
      expect(screen.getByRole("textbox", { name: /Role ARN/ })).toBeVisible();
    });

    it("closes instead of launching a scan when AWS credentials are updated", async () => {
      // Given: the row action opens an existing AWS provider's credentials.
      addProvider.mockResolvedValue({ data: { id: "provider-1" } });
      addCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
      const onOpenChange = vi.fn();
      const user = userEvent.setup();
      render(
        <ProviderWizardModal
          open
          onOpenChange={onOpenChange}
          initialData={{
            providerId: "provider-1",
            providerType: "aws",
            providerUid: "123456789012",
            providerAlias: null,
            secretId: "secret-1",
          }}
        />,
      );

      // When: Back reaches the AWS one-step form, still in update mode.
      await user.click(
        await screen.findByRole("button", { name: "Back to provider" }),
      );
      await user.type(
        await screen.findByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );
      const connect = screen.getByRole("button", { name: "Connect account" });
      await waitFor(() => expect(connect).toBeEnabled());
      await user.click(connect);

      // Then: an update never offers a scan.
      await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
      expect(screen.queryByText("Launch scan")).not.toBeInTheDocument();
    });

    it("returns to the one-step form when the launch step is stepped back from", async () => {
      // Given
      addProvider.mockResolvedValue({ data: { id: "provider-1" } });
      addCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
      const user = await pickAws();
      await user.type(
        screen.getByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );
      const connect = screen.getByRole("button", { name: "Connect account" });
      await waitFor(() => expect(connect).toBeEnabled());
      await user.click(connect);
      await screen.findByText("Launch scan");

      // When
      await user.click(screen.getByRole("button", { name: "Back to form" }));

      // Then: AWS has no separate credentials step, so it lands on its own form.
      expect(
        await screen.findByRole("textbox", { name: /Role ARN/ }),
      ).toBeVisible();
      expect(screen.queryByText("Credential details")).not.toBeInTheDocument();
    });

    it("steps the tour aside once the account can be connected", async () => {
      // Given
      vi.mocked(endActiveTour).mockClear();
      const user = await pickAws();

      // When
      await user.type(
        screen.getByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );

      // Then: the footer sits outside the tour's spotlight, so the tour ends
      // right when the user is ready to press Connect account.
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: "Connect account" }),
        ).toBeEnabled(),
      );
      expect(endActiveTour).toHaveBeenCalled();
    });

    it("goes back to the provider list", async () => {
      // Given
      const user = await pickAws();

      // When
      await user.click(screen.getByRole("button", { name: "Back" }));

      // Then
      expect(
        await screen.findByRole("option", { name: /Microsoft Azure/ }),
      ).toBeVisible();
      expect(
        screen.queryByRole("textbox", { name: /Role ARN/ }),
      ).not.toBeInTheDocument();
    });
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

    // Then: an unanswered discovery cannot vouch for Registry availability.
    expect(
      screen.queryByRole("tab", { name: "Registry" }),
    ).not.toBeInTheDocument();

    // When
    await user.click(
      screen.getByRole("button", { name: "Retry Registry providers" }),
    );

    // Then
    expect(
      await screen.findByRole("option", { name: "Acme Cloud Registry" }),
    ).toBeVisible();
    expect(screen.getByRole("tab", { name: "Registry" })).toBeVisible();
    expect(
      screen.queryByText("Registry providers could not be loaded"),
    ).not.toBeInTheDocument();
  });

  it("keeps the Registry tab with a retry when eligible discovery fails", async () => {
    // Given: Cloud with Registry enabled, but the catalog read failed.
    getInstalledRegistryProviderOptions.mockResolvedValueOnce({
      status: "error",
    });
    const user = userEvent.setup();
    render(<ProviderWizardModal open onOpenChange={vi.fn()} />);
    await screen.findByText("Registry providers could not be loaded");

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));

    // Then
    expect(screen.getByText("No Registry providers available.")).toBeVisible();
  });
});
