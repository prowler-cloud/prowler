import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { ScanConfigurationData } from "@/types/scan-configurations";

import { ManageScanConfigModal } from "./manage-scan-config-modal";

const { setScanConfigurationProvidersMock, toastMock } = vi.hoisted(() => ({
  setScanConfigurationProvidersMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/scan-configurations", () => ({
  setScanConfigurationProviders: setScanConfigurationProvidersMock,
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: toastMock }),
}));

vi.mock("@/components/shadcn/custom/custom-link", () => ({
  CustomLink: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
}));

// Radix Select relies on pointer-capture and scrollIntoView, which jsdom does
// not implement. Polyfill them so the dropdown can open in tests.
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    configurable: true,
    value: vi.fn(() => false),
  });
  Object.defineProperty(HTMLElement.prototype, "setPointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: vi.fn(),
  });
});

const makeConfig = (
  id: string,
  name: string,
  providers: string[],
): ScanConfigurationData => ({
  type: "scan-configurations",
  id,
  attributes: {
    inserted_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
    name,
    configuration: {},
    providers,
  },
});

const renderModal = (
  overrides: Partial<React.ComponentProps<typeof ManageScanConfigModal>> = {},
) => {
  const onOpenChange = vi.fn();
  const onSaved = vi.fn();
  const props: React.ComponentProps<typeof ManageScanConfigModal> = {
    open: true,
    onOpenChange,
    providerId: "provider-1",
    providerLabel: "AWS App Account",
    scanConfigs: [
      makeConfig("config-a", "Config A", []),
      makeConfig("config-b", "Config B", []),
    ],
    currentConfigId: null,
    onSaved,
    ...overrides,
  };

  render(<ManageScanConfigModal {...props} />);
  return { onOpenChange, onSaved, props };
};

const openSelectAndChoose = async (
  user: ReturnType<typeof userEvent.setup>,
  optionName: RegExp,
) => {
  await user.click(
    screen.getByRole("combobox", { name: /scan configuration/i }),
  );
  await user.click(await screen.findByRole("option", { name: optionName }));
};

const clickSave = (user: ReturnType<typeof userEvent.setup>) =>
  user.click(screen.getByRole("button", { name: /^save$/i }));

describe("ManageScanConfigModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setScanConfigurationProvidersMock.mockResolvedValue({
      success: "Scan Configuration updated successfully!",
    });
  });

  it("has an accessible label on the configuration select", () => {
    renderModal();

    expect(
      screen.getByRole("combobox", { name: /scan configuration/i }),
    ).toBeInTheDocument();
  });

  it("attaches the provider to the chosen configuration", async () => {
    // Given an unattached provider.
    const user = userEvent.setup();
    const { onOpenChange, onSaved } = renderModal({ currentConfigId: null });

    // When the user picks "Config A" and saves.
    await openSelectAndChoose(user, /^config a$/i);
    await clickSave(user);

    // Then the provider is added to that config's provider list.
    await waitFor(() =>
      expect(setScanConfigurationProvidersMock).toHaveBeenCalledWith(
        "config-a",
        ["provider-1"],
      ),
    );
    expect(onSaved).toHaveBeenCalledTimes(1);
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("detaches the provider when Default is selected", async () => {
    // Given a provider currently attached to Config A (alongside another).
    const user = userEvent.setup();
    const { onOpenChange, onSaved } = renderModal({
      currentConfigId: "config-a",
      scanConfigs: [
        makeConfig("config-a", "Config A", ["provider-1", "provider-2"]),
        makeConfig("config-b", "Config B", []),
      ],
    });

    // When the user switches back to Default and saves.
    await openSelectAndChoose(user, /^default$/i);
    await clickSave(user);

    // Then only this provider is dropped — the rest stay attached.
    await waitFor(() =>
      expect(setScanConfigurationProvidersMock).toHaveBeenCalledWith(
        "config-a",
        ["provider-2"],
      ),
    );
    expect(onSaved).toHaveBeenCalledTimes(1);
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("moves the provider to another configuration", async () => {
    // Given a provider attached to Config A.
    const user = userEvent.setup();
    renderModal({
      currentConfigId: "config-a",
      scanConfigs: [
        makeConfig("config-a", "Config A", ["provider-1"]),
        makeConfig("config-b", "Config B", []),
      ],
    });

    // When the user picks Config B and saves.
    await openSelectAndChoose(user, /^config b$/i);
    await clickSave(user);

    // Then the provider is attached to Config B (the backend detaches it from A).
    await waitFor(() =>
      expect(setScanConfigurationProvidersMock).toHaveBeenCalledWith(
        "config-b",
        ["provider-1"],
      ),
    );
  });

  it("does not call the action when the selection is unchanged", async () => {
    // Given a provider already attached to Config A.
    const user = userEvent.setup();
    const { onOpenChange } = renderModal({
      currentConfigId: "config-a",
      scanConfigs: [makeConfig("config-a", "Config A", ["provider-1"])],
    });

    // When the user saves without changing the selection.
    await clickSave(user);

    // Then no request is sent, and the modal just closes.
    expect(setScanConfigurationProvidersMock).not.toHaveBeenCalled();
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("surfaces a destructive toast and keeps the modal open on failure", async () => {
    // Given the action returns a field error.
    const user = userEvent.setup();
    setScanConfigurationProvidersMock.mockResolvedValue({
      errors: { general: "Boom" },
    });
    const { onOpenChange, onSaved } = renderModal({ currentConfigId: null });

    // When the user attaches and saves.
    await openSelectAndChoose(user, /^config a$/i);
    await clickSave(user);

    // Then the error is toasted and the modal stays open for a retry.
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          description: "Boom",
        }),
      ),
    );
    expect(onSaved).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalled();
  });

  it("resets a cancelled selection when the modal is reopened", async () => {
    // Given a provider with no attached config.
    const user = userEvent.setup();
    const baseProps: React.ComponentProps<typeof ManageScanConfigModal> = {
      open: true,
      onOpenChange: vi.fn(),
      providerId: "provider-1",
      providerLabel: "AWS App Account",
      scanConfigs: [
        makeConfig("config-a", "Config A", []),
        makeConfig("config-b", "Config B", []),
      ],
      currentConfigId: null,
      onSaved: vi.fn(),
    };
    const { rerender } = render(<ManageScanConfigModal {...baseProps} />);

    // When the user picks Config A but closes the modal without saving.
    await openSelectAndChoose(user, /^config a$/i);
    rerender(<ManageScanConfigModal {...baseProps} open={false} />);

    // And reopens it for the same (still unattached) provider.
    rerender(<ManageScanConfigModal {...baseProps} open />);

    // Then the selection falls back to Default — the stale choice is gone, so
    // saving without touching the dropdown sends nothing.
    await clickSave(user);
    expect(setScanConfigurationProvidersMock).not.toHaveBeenCalled();
  });
});
