import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { addProvider, updateProvider, getInstalledRegistryProviderOptions } =
  vi.hoisted(() => ({
    addProvider: vi.fn(),
    updateProvider: vi.fn(),
    getInstalledRegistryProviderOptions: vi.fn(),
  }));

vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions: { manage_registry: true } }),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));
vi.mock("@/actions/providers/providers", () => ({
  addProvider,
  updateProvider,
}));
vi.mock("@/actions/providers/registry-provider", () => ({
  addRegistryProvider: vi.fn(),
}));
vi.mock("@/actions/registry/registry", () => ({
  getInstalledRegistryProviderOptions,
}));

import { Toaster } from "@/components/shadcn/toast/Toaster";
import { PRICING_URL } from "@/lib/external-urls";
import { useCloudUpgradeStore } from "@/store/cloud-upgrade/store";

import { ConnectAccountForm } from "./connect-account-form";

describe("provider account aliases", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "access_denied",
    });
  });

  it("saves an alias changed after an account was already created", async () => {
    // Given
    const onSuccess = vi.fn();
    const user = userEvent.setup();
    const account = {
      id: "existing",
      attributes: { provider: "github", uid: "octocat", alias: "Original" },
    };
    addProvider.mockResolvedValue({ data: account });
    updateProvider.mockResolvedValue({
      data: {
        ...account,
        attributes: { ...account.attributes, alias: "Edited" },
      },
    });
    render(<ConnectAccountForm onSuccess={onSuccess} />);
    await user.click(screen.getByRole("option", { name: "GitHub" }));
    await user.type(
      screen.getByRole("textbox", { name: "Username/Organization" }),
      "octocat",
    );
    const alias = screen.getByRole("textbox", {
      name: "Provider alias (optional)",
    });
    await user.type(alias, "Original");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());

    // When
    await user.clear(alias);
    await user.type(alias, "Edited");
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Then
    await waitFor(() =>
      expect(onSuccess).toHaveBeenLastCalledWith({
        id: "existing",
        providerType: "github",
        uid: "octocat",
        alias: "Edited",
      }),
    );
    expect(addProvider).toHaveBeenCalledOnce();
    expect(Object.fromEntries(updateProvider.mock.calls[0][0])).toMatchObject({
      providerId: "existing",
      providerAlias: "Edited",
    });
  });
});

describe("usage limit on provider creation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "access_denied",
    });
  });

  it("offers the plans when the usage limit refuses a new account", async () => {
    // Given
    const user = userEvent.setup();
    addProvider.mockResolvedValue({
      errors: [
        {
          detail: "Your trial has ended.",
          status: "402",
          source: { pointer: "/data" },
          code: "payment_required",
        },
      ],
      status: 402,
    });
    render(
      <>
        <ConnectAccountForm onSuccess={vi.fn()} />
        <Toaster />
      </>,
    );
    await user.click(screen.getByRole("option", { name: "GitHub" }));
    await user.type(
      screen.getByRole("textbox", { name: "Username/Organization" }),
      "octocat",
    );

    // When
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Then
    expect(await screen.findByText("Your trial has ended.")).toBeVisible();
    expect(screen.getByRole("link", { name: "View plans" })).toHaveAttribute(
      "href",
      PRICING_URL,
    );
  });
});

describe("Registry provider source tabs", () => {
  it("explains Registry setup in the Registry tab without claiming a connection failure", async () => {
    // Given
    const user = userEvent.setup();
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "onboarding",
    });
    render(<ConnectAccountForm onSuccess={vi.fn()} />);

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));

    // Then
    expect(
      await screen.findByText("Registry is not connected yet"),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Unlock Registry" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("Registry providers could not be loaded"),
    ).not.toBeInTheDocument();

    // When / Then: the built-in list never gets a banner pushed above it.
    await user.click(screen.getByRole("tab", { name: "All providers" }));
    expect(
      screen.queryByText("Registry is not connected yet"),
    ).not.toBeInTheDocument();
  });

  it("offers the Registry paid plan upgrade in the Registry tab while keeping built-in providers usable", async () => {
    // Given
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "subscription_required",
    });
    const user = userEvent.setup();
    useCloudUpgradeStore.getState().closeCloudUpgrade();
    render(<ConnectAccountForm onSuccess={vi.fn()} />);

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));
    await user.click(
      await screen.findByRole("button", { name: "Unlock Registry" }),
    );

    // Then
    expect(useCloudUpgradeStore.getState().activeFeature).toBe("registry");

    // When
    await user.click(screen.getByRole("tab", { name: "All providers" }));

    // Then
    expect(
      screen.getByRole("option", { name: /Amazon Web Services/ }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Unlock Registry" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("Registry providers could not be loaded"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Retry Registry providers" }),
    ).not.toBeInTheDocument();
    useCloudUpgradeStore.getState().closeCloudUpgrade();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    vi.stubEnv("UI_REGISTRY_ENABLED", "true");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("shows both source tabs before discovery settles and loads Registry providers in place", async () => {
    // Given: Registry discovery is still in flight.
    const user = userEvent.setup();
    let settleDiscovery: (result: {
      status: "ready";
      options: { type: string; label: string }[];
    }) => void = () => {};
    getInstalledRegistryProviderOptions.mockReturnValue(
      new Promise((resolve) => {
        settleDiscovery = resolve;
      }),
    );

    // When
    render(<ConnectAccountForm onSuccess={vi.fn()} />);

    // Then: the tabs are there from the first render.
    expect(screen.getByRole("tab", { name: "All providers" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByRole("tab", { name: "Registry" })).toBeVisible();

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));

    // Then
    expect(
      screen.getByRole("status", { name: "Loading Registry providers" }),
    ).toBeVisible();
    expect(
      screen.queryByText("No Registry providers available."),
    ).not.toBeInTheDocument();

    // When
    await act(async () => {
      settleDiscovery({
        status: "ready",
        options: [{ type: "acme", label: "Acme Cloud" }],
      });
    });

    // Then
    expect(
      screen.getByRole("option", { name: /Acme Cloud Registry/ }),
    ).toBeVisible();
    expect(
      screen.queryByRole("status", { name: "Loading Registry providers" }),
    ).not.toBeInTheDocument();
  });

  it("never mentions Registry outside Cloud, even when discovery would fail", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");
    getInstalledRegistryProviderOptions.mockRejectedValue(new Error("network"));

    // When
    render(<ConnectAccountForm onSuccess={vi.fn()} />);

    // Then
    expect(
      await screen.findByRole("option", { name: /Amazon Web Services/ }),
    ).toBeVisible();
    expect(getInstalledRegistryProviderOptions).not.toHaveBeenCalled();
    expect(
      screen.queryByText("Registry providers could not be loaded"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("tab", { name: "Registry" }),
    ).not.toBeInTheDocument();
  });

  it("hides the source tabs without asking discovery when the deployment has Registry off", () => {
    // Given
    vi.stubEnv("UI_REGISTRY_ENABLED", "false");

    // When
    render(<ConnectAccountForm onSuccess={vi.fn()} />);

    // Then
    expect(getInstalledRegistryProviderOptions).not.toHaveBeenCalled();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(
      screen.getByRole("option", { name: /Amazon Web Services/ }),
    ).toBeVisible();
  });

  it("hides the source tabs when discovery denies the user access", async () => {
    // Given
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "access_denied",
    });

    // When
    render(<ConnectAccountForm onSuccess={vi.fn()} />);
    await waitFor(() =>
      expect(getInstalledRegistryProviderOptions).toHaveBeenCalled(),
    );

    // Then
    expect(
      screen.getByRole("option", { name: /Amazon Web Services/ }),
    ).toBeVisible();
    expect(
      screen.queryByRole("tab", { name: "Registry" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("tab", { name: "All providers" }),
    ).not.toBeInTheDocument();
  });

  it("offers a retry in the Registry tab when access is unknown", async () => {
    // Given
    const user = userEvent.setup();
    getInstalledRegistryProviderOptions
      .mockResolvedValueOnce({ status: "unknown" })
      .mockResolvedValueOnce({ status: "ready", options: [] });
    render(<ConnectAccountForm onSuccess={vi.fn()} />);

    // When
    await user.click(screen.getByRole("tab", { name: "Registry" }));

    // Then
    expect(
      await screen.findByText("Registry providers could not be loaded"),
    ).toBeVisible();

    // When
    await user.click(
      screen.getByRole("button", { name: "Retry Registry providers" }),
    );

    // Then
    expect(
      await screen.findByText("No Registry providers available."),
    ).toBeVisible();
    expect(
      screen.queryByText("Registry providers could not be loaded"),
    ).not.toBeInTheDocument();
    expect(getInstalledRegistryProviderOptions).toHaveBeenCalledTimes(2);
  });

  it("shows a retry in flight, ignores repeat clicks and keeps focus on the button", async () => {
    // Given
    const user = userEvent.setup();
    let settleRetry: (result: { status: "error" }) => void = () => {};
    getInstalledRegistryProviderOptions
      .mockResolvedValueOnce({ status: "error" })
      .mockReturnValueOnce(
        new Promise((resolve) => {
          settleRetry = resolve;
        }),
      );
    render(<ConnectAccountForm onSuccess={vi.fn()} />);
    await user.click(screen.getByRole("tab", { name: "Registry" }));
    const retry = await screen.findByRole("button", {
      name: "Retry Registry providers",
    });

    // When
    await user.click(retry);
    await user.click(retry);

    // Then: the warning stays mounted, so the pressed button is never lost.
    expect(retry).toHaveTextContent("Retrying…");
    expect(retry).toHaveAttribute("aria-disabled", "true");
    expect(retry).toHaveFocus();
    expect(getInstalledRegistryProviderOptions).toHaveBeenCalledTimes(2);

    // When: the retry fails again
    settleRetry({ status: "error" });

    // Then
    await waitFor(() =>
      expect(retry).toHaveTextContent("Retry Registry providers"),
    );
    expect(retry).not.toHaveAttribute("aria-disabled", "true");
  });

  it("keeps a retry in flight when an artifact change reloads discovery meanwhile", async () => {
    // Given
    const user = userEvent.setup();
    let settleRetry: (result: { status: "error" }) => void = () => {};
    getInstalledRegistryProviderOptions
      .mockResolvedValueOnce({ status: "error" })
      .mockReturnValueOnce(
        new Promise((resolve) => {
          settleRetry = resolve;
        }),
      )
      .mockResolvedValueOnce({ status: "error" });
    render(<ConnectAccountForm onSuccess={vi.fn()} />);
    await user.click(screen.getByRole("tab", { name: "Registry" }));
    const retry = await screen.findByRole("button", {
      name: "Retry Registry providers",
    });
    await user.click(retry);

    // When: an unrelated reload settles before the retry does
    window.dispatchEvent(new CustomEvent("registry-artifacts-changed"));
    await waitFor(() =>
      expect(getInstalledRegistryProviderOptions).toHaveBeenCalledTimes(3),
    );
    await user.click(retry);

    // Then: only the retry itself may end the retry
    expect(retry).toHaveTextContent("Retrying…");
    expect(getInstalledRegistryProviderOptions).toHaveBeenCalledTimes(3);

    // When
    settleRetry({ status: "error" });

    // Then
    await waitFor(() =>
      expect(retry).toHaveTextContent("Retry Registry providers"),
    );
  });
});
