import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { refreshMock, scanOnDemandMock } = vi.hoisted(() => ({
  refreshMock: vi.fn(),
  scanOnDemandMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    refresh: refreshMock,
  }),
}));

vi.mock("@/actions/scans", () => ({
  scanOnDemand: scanOnDemandMock,
}));

vi.mock("@/components/ui/toast", () => ({
  toast: vi.fn(),
}));

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    children,
    open,
    title,
  }: {
    children: React.ReactNode;
    open: boolean;
    title: string;
  }) =>
    open ? (
      <div role="dialog" aria-label={title}>
        {children}
      </div>
    ) : null,
}));

vi.mock("@/components/ui/entities", () => ({
  EntityInfo: ({
    entityAlias,
    entityId,
  }: {
    entityAlias?: string;
    entityId?: string;
  }) => <>{entityAlias || entityId}</>,
}));

vi.mock("@/components/shadcn", async () => {
  const actual = await vi.importActual<typeof import("@/components/shadcn")>(
    "@/components/shadcn",
  );

  return {
    ...actual,
    Select: ({
      children,
      value = "",
      onValueChange,
    }: {
      children: React.ReactNode;
      value?: string;
      onValueChange?: (value: string) => void;
    }) => (
      <select
        aria-label="Providers"
        value={value}
        onChange={(event) => onValueChange?.(event.target.value)}
      >
        <option value="" hidden disabled>
          Select a provider
        </option>
        {children}
      </select>
    ),
    SelectTrigger: () => null,
    SelectContent: ({ children }: { children: React.ReactNode }) => (
      <>{children}</>
    ),
    SelectItem: ({
      children,
      value,
      disabled,
    }: {
      children: React.ReactNode;
      value: string;
      disabled?: boolean;
    }) => (
      <option value={value} disabled={disabled}>
        {children}
      </option>
    ),
    SelectValue: () => null,
  };
});

import { LaunchScanModal } from "./launch-scan-modal";

const provider = {
  id: "provider-1",
  type: "providers" as const,
  attributes: {
    provider: "aws" as const,
    uid: "123456789012",
    alias: "Production",
    status: "completed" as const,
    resources: 0,
    connection: {
      connected: true,
      last_checked_at: "2026-04-13T00:00:00Z",
    },
    scanner_args: {
      only_logs: false,
      excluded_checks: [],
      aws_retries_max_attempts: 3,
    },
    inserted_at: "2026-04-13T00:00:00Z",
    updated_at: "2026-04-13T00:00:00Z",
    created_by: {
      object: "user",
      id: "user-1",
    },
  },
  relationships: {
    secret: {
      data: null,
    },
    provider_groups: {
      meta: {
        count: 0,
      },
      data: [],
    },
  },
};

const disconnectedProvider = {
  ...provider,
  id: "provider-2",
  attributes: {
    ...provider.attributes,
    alias: "Disconnected",
    uid: "210987654321",
    connection: {
      connected: false,
      last_checked_at: "2026-05-20T11:46:38.834045Z",
    },
  },
};

describe("LaunchScanModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });
  });

  it("renders a single-select provider picker with each provider as an option", () => {
    render(
      <LaunchScanModal
        open
        onOpenChange={vi.fn()}
        providers={[provider, disconnectedProvider]}
      />,
    );

    expect(screen.getByLabelText("Providers")).toBeVisible();
    expect(screen.getByRole("option", { name: "Production" })).toBeEnabled();
    expect(screen.getByRole("option", { name: "Disconnected" })).toBeDisabled();
  });

  it("disables disconnected providers in the launch selector", () => {
    render(
      <LaunchScanModal
        open
        onOpenChange={vi.fn()}
        providers={[provider, disconnectedProvider]}
      />,
    );

    expect(screen.getByRole("option", { name: "Disconnected" })).toBeDisabled();
  });

  it("submits alias as scanName so the API stores it as the scan alias", async () => {
    const user = userEvent.setup();

    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
    await user.type(screen.getByLabelText("Alias"), "Production audit");
    await user.click(screen.getByRole("button", { name: /launch scan/i }));

    await waitFor(() => expect(scanOnDemandMock).toHaveBeenCalled());

    const formData = scanOnDemandMock.mock.calls[0][0] as FormData;
    expect(formData.get("providerId")).toBe(provider.id);
    expect(formData.get("scanName")).toBe("Production audit");
    expect(formData.get("scanNote")).toBeNull();
  });

  it("accepts scan aliases up to the API limit of 100 characters", async () => {
    const user = userEvent.setup();
    const alias = "a".repeat(100);

    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
    await user.type(screen.getByLabelText("Alias"), alias);
    await user.click(screen.getByRole("button", { name: /launch scan/i }));

    await waitFor(() => expect(scanOnDemandMock).toHaveBeenCalled());

    const formData = scanOnDemandMock.mock.calls[0][0] as FormData;
    expect(formData.get("scanName")).toBe(alias);
  });

  it("rejects scan aliases over the API limit of 100 characters", async () => {
    const user = userEvent.setup();

    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
    await user.type(screen.getByLabelText("Alias"), "a".repeat(101));
    await user.click(screen.getByRole("button", { name: /launch scan/i }));

    expect(
      await screen.findByText(/alias must not exceed 100 characters/i),
    ).toBeInTheDocument();
    expect(scanOnDemandMock).not.toHaveBeenCalled();
  });

  it("does not show the old scan note label", () => {
    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    expect(screen.queryByLabelText("Scan Note")).not.toBeInTheDocument();
    expect(screen.queryByText("Scan Note (optional)")).not.toBeInTheDocument();
  });

  it("surfaces JSON:API errors from scanOnDemand and skips the success toast", async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    const { toast } = await import("@/components/ui/toast");
    scanOnDemandMock.mockResolvedValueOnce({
      errors: [{ detail: "Provider already has a scan in progress" }],
    });

    render(
      <LaunchScanModal
        open
        onOpenChange={onOpenChange}
        providers={[provider]}
      />,
    );

    await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
    await user.click(screen.getByRole("button", { name: /launch scan/i }));

    expect(
      await screen.findByText("Provider already has a scan in progress"),
    ).toBeInTheDocument();
    expect(toast).not.toHaveBeenCalled();
    expect(refreshMock).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });
});
