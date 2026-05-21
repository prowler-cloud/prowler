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

vi.mock("@/app/(prowler)/_overview/_components/accounts-selector", () => ({
  AccountsSelector: ({
    providers,
    onBatchChange,
    selectedValues,
    id,
  }: {
    providers: { id: string; attributes: { alias: string; uid: string } }[];
    onBatchChange: (filterKey: string, values: string[]) => void;
    selectedValues: string[];
    id?: string;
  }) => (
    <div>
      <input aria-label="Search accounts" placeholder="Search accounts..." />
      <select
        id={id}
        aria-label="Providers"
        value={selectedValues[0] ?? ""}
        onChange={(event) =>
          onBatchChange("provider_id__in", [event.target.value])
        }
      >
        <option value="">All accounts</option>
        {providers.map((provider) => (
          <option key={provider.id} value={provider.id}>
            {provider.attributes.alias || provider.attributes.uid}
          </option>
        ))}
      </select>
    </div>
  ),
}));

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

describe("LaunchScanModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });
  });

  it("shows a searchable provider selector", () => {
    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    expect(screen.getByPlaceholderText("Search accounts...")).toBeVisible();
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

  it("does not show the old scan note label", () => {
    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    expect(screen.queryByLabelText("Scan Note")).not.toBeInTheDocument();
    expect(screen.queryByText("Scan Note (optional)")).not.toBeInTheDocument();
  });
});
