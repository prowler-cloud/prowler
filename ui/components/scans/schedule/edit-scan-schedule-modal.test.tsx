import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { refreshMock, removeScheduleMock, toastMock, updateScheduleMock } =
  vi.hoisted(() => ({
    refreshMock: vi.fn(),
    removeScheduleMock: vi.fn(),
    toastMock: vi.fn(),
    updateScheduleMock: vi.fn(),
  }));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

vi.mock("@/actions/schedules", () => ({
  removeSchedule: removeScheduleMock,
  updateSchedule: updateScheduleMock,
}));

vi.mock("@/components/ui/toast", () => ({
  toast: toastMock,
}));

vi.mock("@/components/ui/entities", () => ({
  EntityInfo: () => null,
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
});
