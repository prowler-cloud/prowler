import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Toaster } from "@/components/shadcn/toast/Toaster";
import { resetToasts } from "@/components/shadcn/toast/use-toast";
import {
  PROVIDER_FUNNEL_EVENT,
  type ProviderFunnelDetail,
} from "@/lib/provider-funnel/provider-funnel-events";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { useUIStore } from "@/store/ui/store";
import { CONNECTION_CHECK_STATUS } from "@/types/providers";

import { ProviderWizardModal } from "./provider-wizard-modal";

const {
  addCredentialsProvider,
  addProvider,
  addRegistryProvider,
  getInstalledRegistryProviderOptions,
  getProviderSchemas,
  saveDynamicProviderCredentials,
  testProviderConnection,
  updateCredentialsProvider,
  updateProvider,
} = vi.hoisted(() => ({
  addCredentialsProvider: vi.fn(),
  addProvider: vi.fn(),
  addRegistryProvider: vi.fn(),
  getInstalledRegistryProviderOptions: vi.fn(),
  getProviderSchemas: vi.fn(),
  saveDynamicProviderCredentials: vi.fn(),
  testProviderConnection: vi.fn(),
  updateCredentialsProvider: vi.fn(),
  updateProvider: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
  usePathname: () => "/providers",
}));
const { getInvitationRoles, sendInvite, session } = vi.hoisted(() => ({
  getInvitationRoles: vi.fn(),
  sendInvite: vi.fn(),
  // Mutable: only the permissions differ between cases.
  session: {
    data: { tenantId: "tenant-abc" } as {
      tenantId: string;
      user?: { permissions: Record<string, boolean> };
    },
  },
}));

vi.mock("next-auth/react", () => ({
  useSession: () => ({ data: session.data, status: "authenticated" }),
}));
vi.mock("@/actions/invitations/roles", () => ({ getInvitationRoles }));
vi.mock("@/actions/invitations/invitation", () => ({ sendInvite }));
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
  async () => import("../workflow/forms/provider-picker"),
);
vi.mock("@/actions/providers/provider-schemas", () => ({
  getProviderSchemas,
}));
vi.mock("@/actions/providers/dynamic-provider-credentials", () => ({
  saveDynamicProviderCredentials,
}));
vi.mock("@/hooks/use-scroll-hint", () => ({
  useScrollHint: () => ({ showScrollHint: false }),
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

describe("provider wizard", () => {
  beforeEach(() => {
    // Registry discovery only runs in Cloud with Registry enabled.
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    vi.stubEnv("UI_REGISTRY_ENABLED", "true");
    useProviderWizardStore.getState().reset();
    resetToasts();
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "ready",
      options: [{ type: "acme", label: "Acme Cloud" }],
    });
    testProviderConnection.mockResolvedValue({
      status: CONNECTION_CHECK_STATUS.SUCCESS,
      error: null,
    });
    updateCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
    updateProvider.mockResolvedValue({ data: { id: "provider-1" } });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    session.data = { tenantId: "tenant-abc" };
  });

  describe("when the user picks a Registry provider", () => {
    beforeEach(() => {
      getProviderSchemas.mockResolvedValue({
        status: "success",
        providerType: "acme",
        secretTypes: {
          api_key: {
            type: "object",
            properties: {
              token: {
                type: "string",
                title: "API token",
                format: "password",
                writeOnly: true,
              },
            },
            required: ["token"],
          },
        },
      });
      saveDynamicProviderCredentials.mockResolvedValue({
        status: "saved",
        secretId: "secret-acme",
      });
    });

    async function fillAcme() {
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
        await screen.findByRole("textbox", { name: "Provider UID" }),
        "acme-account",
      );
      await user.type(await screen.findByLabelText(/API token/), "token");
      return user;
    }

    it("registers the account, stores its credentials and tests them in one step", async () => {
      // Given
      useUIStore.setState({ hasProviders: false, hasProvidersResolved: true });
      addRegistryProvider.mockResolvedValue({ data: { id: "account" } });
      const user = await fillAcme();

      // When
      await user.click(
        screen.getByRole("button", { name: "Connect provider" }),
      );

      // Then
      expect(await screen.findByText("Launch scan")).toBeVisible();
      expect(saveDynamicProviderCredentials).toHaveBeenCalledWith({
        providerId: "account",
        secretType: "api_key",
        secret: { token: "token" },
      });
      expect(testProviderConnection).toHaveBeenCalledWith("account");
      // The sidebar stops offering Add Provider without waiting for a reload.
      expect(useUIStore.getState().hasProviders).toBe(true);
    });

    it("shows an account conflict on its id and retries the same account", async () => {
      // Given
      addRegistryProvider
        .mockResolvedValueOnce({
          errors: [
            {
              detail: "Provider with this uid already exists.",
              source: { pointer: "/data/attributes/uid" },
            },
          ],
        })
        .mockResolvedValueOnce({ data: { id: "account" } });
      const user = await fillAcme();

      // When
      await user.click(
        screen.getByRole("button", { name: "Connect provider" }),
      );

      // Then
      expect(
        await screen.findByText("Provider with this uid already exists."),
      ).toBeVisible();
      expect(saveDynamicProviderCredentials).not.toHaveBeenCalled();

      // When / Then: the action reads "Connect provider" again once the
      // refused attempt has settled.
      await user.click(
        await screen.findByRole("button", { name: "Connect provider" }),
      );
      expect(await screen.findByText("Launch scan")).toBeVisible();
      expect(addRegistryProvider).toHaveBeenCalledTimes(2);
    });
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

      // Then: the connection is tested in the same step, then the scan follows.
      expect(await screen.findByText("Launch scan")).toBeVisible();
      const progress = screen.getByRole("navigation", {
        name: "Wizard progress",
      });
      expect(progress).toHaveTextContent(/Connect Provider/);
      expect(progress).toHaveTextContent(/Launch Scan/);
      expect(progress).not.toHaveTextContent(/Authenticate|Validate/);
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
        status: CONNECTION_CHECK_STATUS.FAILED,
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

      // When: the wizard opens straight on the account's credentials.
      expect(
        screen.getByRole("navigation", { name: "Wizard progress" }),
      ).toHaveTextContent("Update Credentials");
      await user.type(
        await screen.findByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );
      const connect = screen.getByRole("button", { name: "Save and test" });
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

      // Then: the connect step comes back with what was typed.
      expect(
        await screen.findByRole("textbox", { name: /Role ARN/ }),
      ).toHaveValue(ROLE_ARN);
    });

    it("closes the wizard once a teammate has been invited to connect the account instead", async () => {
      // Given: a user who can invite but cannot reach the account.
      session.data = {
        tenantId: "tenant-abc",
        user: { permissions: { manage_account: true } },
      };
      getInvitationRoles.mockResolvedValue([
        { id: "22222222-2222-4222-8222-222222222222", name: "admin" },
      ]);
      sendInvite.mockResolvedValue({
        data: {
          id: "inv-1",
          attributes: {
            email: "teammate@company.com",
            token: "abc123DEF45678",
          },
        },
      });
      const funnelSignals: ProviderFunnelDetail[] = [];
      const recordFunnelSignal: EventListener = (event) => {
        funnelSignals.push((event as CustomEvent<ProviderFunnelDetail>).detail);
      };
      window.addEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelSignal);
      const onOpenChange = vi.fn();
      const user = userEvent.setup();
      render(<ProviderWizardModal open onOpenChange={onOpenChange} />);
      await screen.findByRole("option", { name: "Acme Cloud Registry" });
      await user.click(
        screen.getByRole("option", { name: /Amazon Web Services/ }),
      );

      // When
      await user.click(
        await screen.findByRole("radio", { name: /invite a teammate/i }),
      );
      await user.type(
        await screen.findByRole("textbox", { name: /Teammate email/ }),
        "teammate@company.com",
      );
      const send = screen.getByRole("button", { name: "Send invitation" });
      await waitFor(() => expect(send).toBeEnabled());
      await user.click(send);
      await user.click(await screen.findByRole("button", { name: "Done" }));
      window.removeEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelSignal);

      // Then: no account was created, so the wizard closes instead of launching.
      expect(onOpenChange).toHaveBeenCalledWith(false);
      expect(screen.queryByText("Launch scan")).not.toBeInTheDocument();
      expect(funnelSignals.at(-1)).toEqual({
        step: "wizard_closed",
        lastStep: "connect",
        providerCreated: false,
      });
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
    expect(
      await screen.findByRole("option", { name: /Amazon Web Services/ }),
    ).toBeVisible();

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));
    await user.click(
      await screen.findByRole("button", { name: "Retry Registry providers" }),
    );

    // Then
    expect(
      await screen.findByRole("option", { name: "Acme Cloud Registry" }),
    ).toBeVisible();
    expect(
      screen.queryByText("Registry providers could not be loaded"),
    ).not.toBeInTheDocument();
  });

  it("shows the retry inside the Registry tab when eligible discovery fails", async () => {
    // Given: Cloud with Registry enabled, but the catalog read failed.
    getInstalledRegistryProviderOptions.mockResolvedValueOnce({
      status: "error",
    });
    const user = userEvent.setup();
    render(<ProviderWizardModal open onOpenChange={vi.fn()} />);

    // When
    await user.click(await screen.findByRole("tab", { name: "Registry" }));

    // Then
    expect(
      await screen.findByText("Registry providers could not be loaded"),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Retry Registry providers" }),
    ).toBeVisible();
    expect(
      screen.queryByText("No Registry providers available."),
    ).not.toBeInTheDocument();
  });
});
