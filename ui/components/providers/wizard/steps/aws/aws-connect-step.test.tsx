import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  PROVIDER_FUNNEL_EVENT,
  type ProviderFunnelDetail,
} from "@/lib/provider-funnel/provider-funnel-events";
import { useProviderWizardStore } from "@/store/provider-wizard/store";

import { AwsConnectStep } from "./aws-connect-step";
import type { AwsConnectUiState } from "./types";

const { addProvider, addCredentialsProvider, openCloudUpgradeMock } =
  vi.hoisted(() => ({
    addProvider: vi.fn(),
    addCredentialsProvider: vi.fn(),
    openCloudUpgradeMock: vi.fn(),
  }));

vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: { tenantId: "tenant-abc" },
    status: "authenticated",
  }),
}));
vi.mock("@/actions/providers/providers", () => ({
  addProvider,
  addCredentialsProvider,
}));
vi.mock("@/store", () => ({
  useCloudUpgradeStore: (
    selector: (state: {
      openCloudUpgrade: typeof openCloudUpgradeMock;
    }) => unknown,
  ) => selector({ openCloudUpgrade: openCloudUpgradeMock }),
}));

const FORM_ID = "aws-connect-test-form";
const ROLE_ARN = "arn:aws:iam::123456789012:role/ProwlerScan";

// Stands in for the wizard footer: the step only publishes its UI state.
function Harness({
  onConnected,
  onSelectOrganizations,
}: {
  onConnected: () => void;
  onSelectOrganizations: () => void;
}) {
  const [uiState, setUiState] = useState<AwsConnectUiState | null>(null);
  return (
    <>
      <AwsConnectStep
        formId={FORM_ID}
        onConnected={onConnected}
        onSelectOrganizations={onSelectOrganizations}
        onUiStateChange={setUiState}
      />
      <button
        type="submit"
        form={FORM_ID}
        disabled={uiState?.actionDisabled ?? true}
      >
        {uiState?.actionLabel ?? "Connect account"}
      </button>
    </>
  );
}

function renderStep() {
  const onConnected = vi.fn();
  const onSelectOrganizations = vi.fn();
  render(
    <Harness
      onConnected={onConnected}
      onSelectOrganizations={onSelectOrganizations}
    />,
  );
  return { onConnected, onSelectOrganizations, user: userEvent.setup() };
}

const connectButton = () =>
  screen.getByRole("button", { name: "Connect account" });

describe("AwsConnectStep", () => {
  const funnelSignals: ProviderFunnelDetail[] = [];
  const recordFunnelSignal: EventListener = (event) => {
    funnelSignals.push((event as CustomEvent<ProviderFunnelDetail>).detail);
  };

  beforeEach(() => {
    funnelSignals.length = 0;
    window.addEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelSignal);
    vi.clearAllMocks();
    sessionStorage.clear();
    useProviderWizardStore.getState().reset();
    addProvider.mockResolvedValue({ data: { id: "provider-1" } });
    addCredentialsProvider.mockResolvedValue({ data: { id: "secret-1" } });
  });

  afterEach(() => {
    window.removeEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelSignal);
    vi.unstubAllEnvs();
  });

  describe("in Prowler Cloud", () => {
    beforeEach(() => {
      vi.stubEnv("UI_CLOUD_ENABLED", "true");
    });

    it("creates the role from the shared stack and connects with just its ARN", async () => {
      // Given
      const { onConnected, user } = renderStep();

      // Then: the button opens the shared template with the External ID filled in;
      // the AccountId parameter defaults to Prowler Cloud's account there.
      const quickCreate = screen.getByRole("link", {
        name: /Create the IAM role in AWS/i,
      });
      expect(quickCreate).toHaveAttribute(
        "href",
        expect.stringContaining("prowler-scan-role.yml"),
      );
      expect(quickCreate).toHaveAttribute(
        "href",
        expect.stringContaining("param_ExternalId=tenant-abc"),
      );
      expect(connectButton()).toBeDisabled();

      // When
      await user.type(
        screen.getByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );

      // Then
      expect(
        await screen.findByText(/Account 123456789012 will be added/),
      ).toBeVisible();
      await waitFor(() => expect(connectButton()).toBeEnabled());

      // When
      await user.click(connectButton());

      // Then
      await waitFor(() => expect(onConnected).toHaveBeenCalledOnce());
      const secret = Object.fromEntries(
        (addCredentialsProvider.mock.calls[0][0] as FormData).entries(),
      );
      expect(secret).toMatchObject({
        providerId: "provider-1",
        role_arn: ROLE_ARN,
        external_id: "tenant-abc",
        credentials_type: "aws-sdk-default",
      });
      expect(funnelSignals).toContainEqual({
        step: "account_submitted",
        providerType: "aws",
        via: "role",
        outcome: "success",
      });
    });

    it("shows an account the API already knows on the ARN field and stays on the step", async () => {
      // Given
      addProvider.mockResolvedValueOnce({
        errors: [
          {
            detail: "Provider with this uid already exists.",
            source: { pointer: "/data/attributes/uid" },
          },
        ],
      });
      const { onConnected, user } = renderStep();
      await user.type(
        screen.getByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );
      await waitFor(() => expect(connectButton()).toBeEnabled());

      // When
      await user.click(connectButton());

      // Then
      expect(
        await screen.findByText("Provider with this uid already exists."),
      ).toBeVisible();
      expect(onConnected).not.toHaveBeenCalled();
      expect(funnelSignals).toContainEqual({
        step: "account_submitted",
        providerType: "aws",
        via: "role",
        outcome: "error",
      });
    });

    it("hands the whole-organization choice to the organizations flow", async () => {
      // Given
      const { onSelectOrganizations, user } = renderStep();

      // When
      await user.click(
        screen.getByRole("tab", { name: /Full AWS Organization/ }),
      );

      // Then
      expect(onSelectOrganizations).toHaveBeenCalledOnce();
    });

    it("connects with access keys and the typed account id", async () => {
      // Given
      const { onConnected, user } = renderStep();

      // When
      await user.click(
        screen.getByRole("radio", { name: /Static access keys/ }),
      );
      await user.type(
        screen.getByRole("textbox", { name: /Account ID/ }),
        "210987654321",
      );
      await user.type(
        screen.getByPlaceholderText("Enter the AWS Access Key ID"),
        "AKIAEXAMPLE",
      );
      await user.type(
        screen.getByPlaceholderText("Enter the AWS Secret Access Key"),
        "secret-value",
      );
      await waitFor(() => expect(connectButton()).toBeEnabled());
      await user.click(connectButton());

      // Then
      await waitFor(() => expect(onConnected).toHaveBeenCalledOnce());
      const provider = Object.fromEntries(
        (addProvider.mock.calls[0][0] as FormData).entries(),
      );
      expect(provider).toEqual({
        providerType: "aws",
        providerUid: "210987654321",
      });
    });
  });

  describe("with access keys, when the API refuses the account", () => {
    beforeEach(() => {
      vi.stubEnv("UI_CLOUD_ENABLED", "true");
    });

    it("shows the refusal on the Account ID field and stays on the step", async () => {
      // Given
      addProvider.mockResolvedValueOnce({
        errors: [
          {
            detail: "Provider with this uid already exists.",
            source: { pointer: "/data/attributes/uid" },
          },
        ],
      });
      const { onConnected, user } = renderStep();
      await user.click(
        screen.getByRole("radio", { name: /Static access keys/ }),
      );
      await user.type(
        screen.getByRole("textbox", { name: /Account ID/ }),
        "210987654321",
      );
      await user.type(
        screen.getByPlaceholderText("Enter the AWS Access Key ID"),
        "AKIAEXAMPLE",
      );
      await user.type(
        screen.getByPlaceholderText("Enter the AWS Secret Access Key"),
        "secret-value",
      );
      await waitFor(() => expect(connectButton()).toBeEnabled());

      // When
      await user.click(connectButton());

      // Then
      expect(
        await screen.findByText("Provider with this uid already exists."),
      ).toBeVisible();
      // The field wrapper carries the invalid state for the Account ID input.
      expect(
        screen
          .getByRole("textbox", { name: /Account ID/ })
          .closest("[aria-invalid]"),
      ).toHaveAttribute("aria-invalid", "true");
      expect(onConnected).not.toHaveBeenCalled();
    });
  });

  describe("when the step is left and reopened within the same wizard", () => {
    beforeEach(() => {
      vi.stubEnv("UI_CLOUD_ENABLED", "true");
    });

    it("keeps what was typed, including the chosen access method", async () => {
      // Given
      const onConnected = vi.fn();
      const onSelectOrganizations = vi.fn();
      const user = userEvent.setup();
      const { unmount } = render(
        <Harness
          onConnected={onConnected}
          onSelectOrganizations={onSelectOrganizations}
        />,
      );
      await user.click(
        screen.getByRole("radio", { name: /Static access keys/ }),
      );
      await user.type(
        screen.getByRole("textbox", { name: /Account ID/ }),
        "210987654321",
      );
      await user.type(
        screen.getByRole("textbox", { name: /Provider alias/ }),
        "Staging",
      );

      // When: the organizations tab or the connection test unmounts the step.
      unmount();
      render(
        <Harness
          onConnected={onConnected}
          onSelectOrganizations={onSelectOrganizations}
        />,
      );

      // Then
      expect(
        screen.getByRole("radio", { name: /Static access keys/ }),
      ).toHaveAttribute("aria-checked", "true");
      expect(screen.getByRole("textbox", { name: /Account ID/ })).toHaveValue(
        "210987654321",
      );
      expect(
        screen.getByRole("textbox", { name: /Provider alias/ }),
      ).toHaveValue("Staging");
    });

    it("starts blank again once the wizard is reset", async () => {
      // Given
      const user = userEvent.setup();
      const { unmount } = render(
        <Harness onConnected={vi.fn()} onSelectOrganizations={vi.fn()} />,
      );
      await user.type(
        screen.getByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );
      unmount();

      // When
      useProviderWizardStore.getState().reset();
      render(<Harness onConnected={vi.fn()} onSelectOrganizations={vi.fn()} />);

      // Then
      expect(screen.getByRole("textbox", { name: /Role ARN/ })).toHaveValue("");
    });
  });

  describe("in Prowler Cloud, role creation", () => {
    beforeEach(() => {
      vi.stubEnv("UI_CLOUD_ENABLED", "true");
    });

    it("leads with the one-click stack and keeps the other templates behind a toggle", async () => {
      // Given
      const { user } = renderStep();

      // Then
      expect(
        screen.queryByRole("link", { name: /CloudFormation Template/i }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByRole("link", { name: /Terraform Code/i }),
      ).not.toBeInTheDocument();

      // When
      await user.click(
        screen.getByRole("button", { name: /Other ways to create the role/i }),
      );

      // Then
      expect(
        screen.getByRole("link", { name: /CloudFormation Template/i }),
      ).toHaveAttribute("href", expect.stringContaining("prowler-scan-role"));
      expect(
        screen.getByRole("link", { name: /Terraform Code/i }),
      ).toBeVisible();
    });

    it("never asks which credentials assume the role: Prowler Cloud does", async () => {
      // Given
      const { user } = renderStep();
      await user.click(
        screen.getByRole("button", { name: /Advanced options/i }),
      );

      // Then
      expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
      expect(
        screen.queryByPlaceholderText("Enter the AWS Access Key ID"),
      ).not.toBeInTheDocument();
      expect(
        screen.getByPlaceholderText("Enter the role session name"),
      ).toBeVisible();
    });
  });

  describe("in a self-hosted deployment", () => {
    beforeEach(() => {
      vi.stubEnv("UI_CLOUD_ENABLED", "false");
    });

    it("offers the same one-click role setup, on the shared template", async () => {
      // Given
      const { user } = renderStep();

      // Then: the template keeps the AccountId parameter self-hosted users must edit.
      expect(
        screen.getByRole("link", { name: /Create the IAM role in AWS/i }),
      ).toHaveAttribute(
        "href",
        expect.stringContaining("prowler-scan-role.yml"),
      );

      // When
      await user.click(
        screen.getByRole("button", { name: /Advanced options/i }),
      );

      // Then: keys belong to the "Static access keys" method, never to the role one.
      expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
      expect(
        screen.queryByPlaceholderText("Enter the AWS Access Key ID"),
      ).not.toBeInTheDocument();
      expect(
        screen.getByPlaceholderText("Enter the role session name"),
      ).toBeVisible();
    });

    it("assumes the role with the credentials of the host running Prowler", async () => {
      // Given
      const { onConnected, user } = renderStep();

      // When
      await user.type(
        screen.getByRole("textbox", { name: /Role ARN/ }),
        ROLE_ARN,
      );
      await screen.findByText(/Account 123456789012 will be added/);
      await waitFor(() => expect(connectButton()).toBeEnabled());
      await user.click(connectButton());

      // Then
      await waitFor(() => expect(onConnected).toHaveBeenCalledOnce());
      const secret = Object.fromEntries(
        (addCredentialsProvider.mock.calls[0][0] as FormData).entries(),
      );
      expect(secret).toMatchObject({
        role_arn: ROLE_ARN,
        credentials_type: "aws-sdk-default",
      });
      expect(secret).not.toHaveProperty("aws_access_key_id");
    });
  });
});
