import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  refreshMock,
  removeScheduleMock,
  toastMock,
  updateScheduleMock,
  updateSchedulesBulkMock,
} = vi.hoisted(() => ({
  refreshMock: vi.fn(),
  removeScheduleMock: vi.fn(),
  toastMock: vi.fn(),
  updateScheduleMock: vi.fn(),
  updateSchedulesBulkMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

vi.mock("@/actions/schedules", () => ({
  removeSchedule: removeScheduleMock,
  updateSchedule: updateScheduleMock,
  updateSchedulesBulk: updateSchedulesBulkMock,
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: toastMock,
}));

vi.mock("@/components/icons/providers-badge/provider-type-icon", () => ({
  ProviderTypeIconStack: ({ items }: { items: Array<{ type: string }> }) => (
    <div data-testid="provider-type-icon-stack">
      {items.map((item) => (
        <span key={item.type}>{item.type}</span>
      ))}
    </div>
  ),
}));

vi.mock("@/components/shadcn/entities", () => ({
  EntityInfo: ({
    badge,
    cloudProvider,
    entityAlias,
    icon,
  }: {
    badge?: string;
    cloudProvider?: string;
    entityAlias?: string;
    icon?: React.ReactNode;
  }) => (
    <div data-testid="entity-info">
      {cloudProvider && (
        <span data-testid="single-cloud-provider">{cloudProvider}</span>
      )}
      {icon}
      {entityAlias && <span>{entityAlias}</span>}
      {badge && <span>{badge}</span>}
    </div>
  ),
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

import {
  ACTION_ERROR_API_MESSAGES,
  ACTION_ERROR_MESSAGES,
  ACTION_ERROR_STATUS,
} from "@/lib/action-errors";
import type { ScheduleProps } from "@/types/schedules";

import {
  EDIT_SCAN_SCHEDULE_STATE,
  EditScanScheduleModal,
} from "./edit-scan-schedule-modal";

const provider = {
  providerId: "p1",
  providerType: "aws" as const,
  providerUid: "123456789012",
  providerAlias: "Production",
};

const organizationProviders = [
  provider,
  {
    providerId: "p2",
    providerType: "aws" as const,
    providerUid: "210987654321",
    providerAlias: "Staging",
  },
];

const multiCloudProviders = [
  provider,
  {
    providerId: "p2",
    providerType: "azure" as const,
    providerUid: "azure-subscription",
    providerAlias: "Azure Prod",
  },
  {
    providerId: "p3",
    providerType: "aws" as const,
    providerUid: "210987654321",
    providerAlias: "AWS Staging",
  },
];

const schedule: ScheduleProps = {
  type: "schedules",
  id: "p1",
  attributes: {
    scan_enabled: true,
    scan_frequency: "DAILY",
    scan_hour: 4,
    scan_timezone: "UTC",
    scan_interval_hours: null,
    scan_day_of_week: null,
    scan_day_of_month: null,
  },
  relationships: {
    provider: { data: { type: "providers", id: "p1" } },
  },
};

const renderLoaded = () =>
  render(
    <EditScanScheduleModal
      open
      onOpenChange={vi.fn()}
      provider={provider}
      state={{ kind: EDIT_SCAN_SCHEDULE_STATE.LOADED, schedule }}
    />,
  );

describe("EditScanScheduleModal remove flow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    removeScheduleMock.mockResolvedValue({ success: true });
    updateSchedulesBulkMock.mockResolvedValue({ success: true });
  });

  it("asks for confirmation before removing the schedule", async () => {
    const user = userEvent.setup();
    renderLoaded();

    await user.click(
      screen.getByRole("button", { name: /remove scan schedule/i }),
    );

    expect(removeScheduleMock).not.toHaveBeenCalled();
    expect(
      screen.getByRole("dialog", { name: "Are you absolutely sure?" }),
    ).toBeInTheDocument();
  });

  it("removes the schedule only after confirming", async () => {
    const user = userEvent.setup();
    renderLoaded();

    await user.click(
      screen.getByRole("button", { name: /remove scan schedule/i }),
    );
    const confirmDialog = screen.getByRole("dialog", {
      name: "Are you absolutely sure?",
    });
    await user.click(
      within(confirmDialog).getByRole("button", { name: "Remove" }),
    );

    await waitFor(() => expect(removeScheduleMock).toHaveBeenCalledWith("p1"));
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Scan schedule removed" }),
    );
  });

  it("hides the remove button when the provider has no configured schedule", () => {
    render(
      <EditScanScheduleModal
        open
        onOpenChange={vi.fn()}
        provider={provider}
        state={{
          kind: EDIT_SCAN_SCHEDULE_STATE.LOADED,
          schedule: {
            ...schedule,
            attributes: { ...schedule.attributes, scan_hour: null },
          },
        }}
      />,
    );

    expect(
      screen.queryByRole("button", { name: /remove scan schedule/i }),
    ).not.toBeInTheDocument();
  });

  it("keeps the schedule when the confirmation is cancelled", async () => {
    const user = userEvent.setup();
    renderLoaded();

    await user.click(
      screen.getByRole("button", { name: /remove scan schedule/i }),
    );
    const confirmDialog = screen.getByRole("dialog", {
      name: "Are you absolutely sure?",
    });
    await user.click(
      within(confirmDialog).getByRole("button", { name: "Cancel" }),
    );

    expect(removeScheduleMock).not.toHaveBeenCalled();
  });

  it("saves organization schedules through the bulk endpoint", async () => {
    const user = userEvent.setup();
    render(
      <EditScanScheduleModal
        open
        onOpenChange={vi.fn()}
        providers={organizationProviders}
        targetName="My AWS Organization"
        targetId="o-abc123def4"
        state={{ kind: EDIT_SCAN_SCHEDULE_STATE.LOADED, schedule }}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(updateSchedulesBulkMock).toHaveBeenCalledWith(
        ["p1", "p2"],
        expect.objectContaining({
          scan_enabled: true,
          scan_frequency: "DAILY",
          scan_hour: 4,
        }),
      ),
    );
    expect(updateScheduleMock).not.toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        description: "The scan schedule was updated for 2 providers.",
      }),
    );
  });

  it("uses explicit provider ids for organization bulk schedules", async () => {
    const user = userEvent.setup();
    render(
      <EditScanScheduleModal
        open
        onOpenChange={vi.fn()}
        providers={[organizationProviders[0]]}
        providerIds={["p1", "p2", "p3"]}
        targetName="My AWS Organization"
        targetId="o-abc123def4"
        state={{ kind: EDIT_SCAN_SCHEDULE_STATE.LOADED, schedule }}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(updateSchedulesBulkMock).toHaveBeenCalledWith(
        ["p1", "p2", "p3"],
        expect.objectContaining({
          scan_enabled: true,
          scan_frequency: "DAILY",
          scan_hour: 4,
        }),
      ),
    );
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        description: "The scan schedule was updated for 3 providers.",
      }),
    );
  });

  it("uses the shared subscription error copy when saving is blocked", async () => {
    const user = userEvent.setup();
    updateScheduleMock.mockResolvedValue({
      error: ACTION_ERROR_API_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
      status: ACTION_ERROR_STATUS.PAYMENT_REQUIRED,
    });

    renderLoaded();

    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(
      await screen.findByText(
        ACTION_ERROR_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        ACTION_ERROR_API_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
      ),
    ).not.toBeInTheDocument();
  });

  it("uses the shared subscription error copy when removing is blocked", async () => {
    const user = userEvent.setup();
    removeScheduleMock.mockResolvedValue({
      error: ACTION_ERROR_API_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
      status: ACTION_ERROR_STATUS.PAYMENT_REQUIRED,
    });
    renderLoaded();

    await user.click(
      screen.getByRole("button", { name: /remove scan schedule/i }),
    );
    const confirmDialog = screen.getByRole("dialog", {
      name: "Are you absolutely sure?",
    });
    await user.click(
      within(confirmDialog).getByRole("button", { name: "Remove" }),
    );

    expect(
      await screen.findByText(
        ACTION_ERROR_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        ACTION_ERROR_API_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
      ),
    ).not.toBeInTheDocument();
  });

  it("shows one logo per selected provider type in bulk mode", () => {
    render(
      <EditScanScheduleModal
        open
        onOpenChange={vi.fn()}
        providers={multiCloudProviders}
        targetName="Selected providers"
        state={{ kind: EDIT_SCAN_SCHEDULE_STATE.LOADED, schedule }}
      />,
    );

    const stack = screen.getByTestId("provider-type-icon-stack");
    expect(stack).toHaveTextContent("aws");
    expect(stack).toHaveTextContent("azure");
    expect(
      screen.queryByTestId("single-cloud-provider"),
    ).not.toBeInTheDocument();
  });
});
