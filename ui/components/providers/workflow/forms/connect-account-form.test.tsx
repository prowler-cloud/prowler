import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { addProvider, updateProvider, getInstalledRegistryProviderOptions } =
  vi.hoisted(() => ({
    addProvider: vi.fn(),
    updateProvider: vi.fn(),
    getInstalledRegistryProviderOptions: vi.fn(),
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

describe("Registry provider source tabs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("hides the Registry tab when discovery denies access (Local or flag off)", async () => {
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

  it("shows the Registry tab once discovery confirms the deployment offers it", async () => {
    // Given: Cloud or Private Cloud with Registry enabled and no artifacts yet.
    getInstalledRegistryProviderOptions.mockResolvedValue({
      status: "ready",
      options: [],
    });

    // When
    render(<ConnectAccountForm onSuccess={vi.fn()} />);

    // Then
    expect(await screen.findByRole("tab", { name: "Registry" })).toBeVisible();
    expect(screen.getByRole("tab", { name: "All providers" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });

  it("keeps Registry hidden and offers a retry when access is unknown", async () => {
    // Given
    const user = userEvent.setup();
    getInstalledRegistryProviderOptions
      .mockResolvedValueOnce({ status: "unknown" })
      .mockResolvedValueOnce({ status: "ready", options: [] });

    // When
    render(<ConnectAccountForm onSuccess={vi.fn()} />);

    // Then
    expect(
      await screen.findByText("Registry providers could not be loaded"),
    ).toBeVisible();
    expect(
      screen.queryByRole("tab", { name: "Registry" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Retry Registry providers" }),
    ).toBeVisible();

    // When
    await user.click(
      screen.getByRole("button", { name: "Retry Registry providers" }),
    );

    // Then
    expect(await screen.findByRole("tab", { name: "Registry" })).toBeVisible();
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
});
