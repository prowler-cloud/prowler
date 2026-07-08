import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  getScheduleMock,
  refreshMock,
  scanOnDemandMock,
  scheduleDailyMock,
  searchParamsValue,
  toastMock,
  updateScheduleMock,
} = vi.hoisted(() => ({
  getScheduleMock: vi.fn(),
  refreshMock: vi.fn(),
  scanOnDemandMock: vi.fn(),
  scheduleDailyMock: vi.fn(),
  searchParamsValue: { current: "" },
  toastMock: vi.fn(),
  updateScheduleMock: vi.fn(),
}));

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, "ResizeObserver", {
  writable: true,
  configurable: true,
  value: ResizeObserverMock,
});

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    refresh: refreshMock,
  }),
  useSearchParams: () => new URLSearchParams(searchParamsValue.current),
}));

vi.mock("@/actions/scans", () => ({
  scanOnDemand: scanOnDemandMock,
  scheduleDaily: scheduleDailyMock,
}));

vi.mock("@/actions/schedules", () => ({
  getSchedule: getScheduleMock,
  updateSchedule: updateScheduleMock,
}));

vi.mock("@/components/shadcn/toast", () => ({
  ToastAction: ({ children, ...props }: ComponentProps<"button">) => (
    <button {...props}>{children}</button>
  ),
  toast: toastMock,
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

vi.mock("@/components/shadcn/entities", () => ({
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
    disabledValues = [],
    providers,
    onBatchChange,
    selectedValues,
    id,
    placeholder = "All Providers",
  }: {
    disabledValues?: string[];
    providers: { id: string; attributes: { alias: string; uid: string } }[];
    onBatchChange: (filterKey: string, values: string[]) => void;
    selectedValues: string[];
    id?: string;
    placeholder?: string;
  }) => (
    <div>
      <input aria-label="Search Providers" placeholder="Search Providers..." />
      <select
        id={id}
        aria-label="Providers"
        value={selectedValues[0] ?? ""}
        onChange={(event) =>
          onBatchChange("provider_id__in", [event.target.value])
        }
      >
        <option value="">{placeholder}</option>
        {providers.map((provider) => (
          <option
            key={provider.id}
            value={provider.id}
            disabled={disabledValues.includes(provider.id)}
          >
            {provider.attributes.alias || provider.attributes.uid}
          </option>
        ))}
      </select>
    </div>
  ),
}));

import {
  ACTION_ERROR_API_MESSAGES,
  ACTION_ERROR_MESSAGES,
  ACTION_ERROR_STATUS,
} from "@/lib/action-errors";
import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

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
    searchParamsValue.current = "";
    scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows a searchable provider selector", () => {
    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    expect(screen.getByPlaceholderText("Search Providers...")).toBeVisible();
  });

  it("uses a single-provider placeholder in the launch selector", () => {
    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    expect(
      screen.getByRole("option", { name: "Select a Provider" }),
    ).toBeInTheDocument();
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

  it("adds a toast action to view the scan in progress when another tab is active", async () => {
    const user = userEvent.setup();
    searchParamsValue.current =
      "tab=completed&filter%5Bstate__in%5D=failed&page=3";

    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
    await user.click(screen.getByRole("button", { name: /launch scan/i }));

    await waitFor(() => expect(toastMock).toHaveBeenCalled());

    const toastPayload = toastMock.mock.calls[0]?.[0];
    expect(toastPayload.action).toBeDefined();
    expect(toastPayload.action.props.children.props.href).toBe(
      "/scans?tab=active",
    );
    expect(toastPayload.action.props.children.props.children).toBe("View scan");
  });

  it("does not add a toast action when the in progress tab is active", async () => {
    const user = userEvent.setup();
    searchParamsValue.current = "tab=active";

    render(
      <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
    );

    await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
    await user.click(screen.getByRole("button", { name: /launch scan/i }));

    await waitFor(() => expect(toastMock).toHaveBeenCalled());

    const toastPayload = toastMock.mock.calls[0]?.[0];
    expect(toastPayload.action).toBeUndefined();
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
    expect(toastMock).not.toHaveBeenCalled();
    expect(refreshMock).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  it("maps payment-required scan errors to the shared subscription message", async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    scanOnDemandMock.mockResolvedValueOnce({
      error: ACTION_ERROR_API_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
      status: ACTION_ERROR_STATUS.PAYMENT_REQUIRED,
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
      await screen.findByText(
        ACTION_ERROR_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        ACTION_ERROR_API_MESSAGES[ACTION_ERROR_STATUS.PAYMENT_REQUIRED],
      ),
    ).not.toBeInTheDocument();
    expect(toastMock).not.toHaveBeenCalled();
    expect(refreshMock).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  describe("schedule mode", () => {
    const weeklyScheduleResponse = {
      data: {
        type: "schedules",
        id: provider.id,
        attributes: {
          scan_enabled: true,
          scan_frequency: "WEEKLY",
          scan_hour: 9,
          scan_timezone: "Europe/Madrid",
          scan_interval_hours: null,
          scan_day_of_week: 1,
          scan_day_of_month: null,
        },
      },
    };

    beforeEach(() => {
      getScheduleMock.mockResolvedValue(weeklyScheduleResponse);
      updateScheduleMock.mockResolvedValue({ data: { id: provider.id } });
    });

    const renderAdvanced = () =>
      render(
        <LaunchScanModal
          open
          onOpenChange={vi.fn()}
          providers={[provider]}
          capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
        />,
      );

    it("prefills the provider schedule and saves it through the new API", async () => {
      const user = userEvent.setup();
      renderAdvanced();

      await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
      await user.click(screen.getByRole("radio", { name: "On a schedule" }));

      await waitFor(() =>
        expect(getScheduleMock).toHaveBeenCalledWith(provider.id),
      );

      await user.click(
        await screen.findByRole("button", { name: /save schedule/i }),
      );

      // The payload carries the fetched WEEKLY schedule, proving the prefill.
      await waitFor(() =>
        expect(updateScheduleMock).toHaveBeenCalledWith(
          provider.id,
          expect.objectContaining({
            scan_enabled: true,
            scan_frequency: "WEEKLY",
            scan_hour: 9,
            scan_day_of_week: 1,
          }),
        ),
      );
      expect(scanOnDemandMock).not.toHaveBeenCalled();
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Scan schedule saved" }),
      );
    });

    it("keeps the upcoming local hour when provider scan fields say there is no schedule", async () => {
      // Given
      const user = userEvent.setup();
      vi.setSystemTime(new Date(2026, 5, 10, 11, 59, 0, 0));
      getScheduleMock.mockResolvedValue({
        data: {
          type: "schedules",
          id: provider.id,
          attributes: {
            scan_enabled: true,
            scan_frequency: "DAILY",
            scan_hour: 0,
            scan_timezone: "UTC",
            scan_interval_hours: null,
            scan_day_of_week: null,
            scan_day_of_month: null,
          },
        },
      });
      const providerWithoutSchedule = {
        ...provider,
        attributes: {
          ...provider.attributes,
          scan_enabled: true,
          scan_frequency: "DAILY" as const,
          scan_hour: null,
          scan_timezone: "UTC",
          scan_interval_hours: null,
          scan_day_of_week: null,
          scan_day_of_month: null,
          next_scan_at: null,
          last_scan_at: null,
        },
      };

      render(
        <LaunchScanModal
          open
          onOpenChange={vi.fn()}
          providers={[providerWithoutSchedule]}
          capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
        />,
      );

      // When
      await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
      await user.click(screen.getByRole("radio", { name: "On a schedule" }));

      // Then
      expect(
        await screen.findByRole("combobox", { name: "Scan Time" }),
      ).toHaveTextContent("12:00pm");
      expect(
        screen.getByRole("combobox", { name: "Scan Time" }),
      ).not.toHaveTextContent("12:00am");
      expect(getScheduleMock).not.toHaveBeenCalled();
    });

    it("launches the initial scan when the checkbox is checked", async () => {
      const user = userEvent.setup();
      renderAdvanced();

      await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
      await user.click(screen.getByRole("radio", { name: "On a schedule" }));
      await user.click(
        await screen.findByLabelText(
          "Launch an initial scan now for immediate findings",
        ),
      );
      await user.click(screen.getByRole("button", { name: /save schedule/i }));

      await waitFor(() => expect(updateScheduleMock).toHaveBeenCalled());
      await waitFor(() => expect(scanOnDemandMock).toHaveBeenCalledTimes(1));
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Scan schedule saved and initial scan launched",
        }),
      );
    });

    it("disables Save Schedule until a provider is selected", async () => {
      const user = userEvent.setup();
      renderAdvanced();

      await user.click(screen.getByRole("radio", { name: "On a schedule" }));

      expect(
        screen.getByRole("button", { name: /save schedule/i }),
      ).toBeDisabled();
      expect(getScheduleMock).not.toHaveBeenCalled();
    });

    it("locks schedule mode outside ADVANCED (OSS default)", () => {
      render(
        <LaunchScanModal open onOpenChange={vi.fn()} providers={[provider]} />,
      );

      expect(
        screen.getByRole("radio", { name: "On a schedule" }),
      ).toBeDisabled();
      expect(getScheduleMock).not.toHaveBeenCalled();
    });

    it("hides schedule mode but allows manual scans in MANUAL_ONLY", async () => {
      const user = userEvent.setup();

      render(
        <LaunchScanModal
          open
          onOpenChange={vi.fn()}
          providers={[provider]}
          capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        />,
      );

      expect(screen.queryByRole("radio")).not.toBeInTheDocument();

      await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
      await user.click(screen.getByRole("button", { name: /launch scan/i }));

      await waitFor(() => expect(scanOnDemandMock).toHaveBeenCalledTimes(1));
      expect(getScheduleMock).not.toHaveBeenCalled();
      expect(updateScheduleMock).not.toHaveBeenCalled();
    });

    it("hides the mode selector and blocks over-limit accounts in MANUAL_ONLY", () => {
      render(
        <LaunchScanModal
          open
          onOpenChange={vi.fn()}
          providers={[provider]}
          capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
          isScanLimitReached
        />,
      );

      expect(screen.queryByRole("radio")).not.toBeInTheDocument();
      expect(screen.getByText(/exceeded the usage limit/i)).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: /launch scan/i }),
      ).toBeDisabled();
    });

    it("blocks scans and schedules in BLOCKED", async () => {
      const user = userEvent.setup();

      render(
        <LaunchScanModal
          open
          onOpenChange={vi.fn()}
          providers={[provider]}
          capability={SCAN_SCHEDULE_CAPABILITY.BLOCKED}
        />,
      );

      expect(screen.queryByRole("radio")).not.toBeInTheDocument();
      expect(screen.getByText(/exceeded the usage limit/i)).toBeInTheDocument();

      await user.selectOptions(screen.getByLabelText("Providers"), provider.id);
      await user.click(screen.getByRole("button", { name: /launch scan/i }));

      expect(
        screen.getByRole("button", { name: /launch scan/i }),
      ).toBeDisabled();
      expect(scanOnDemandMock).not.toHaveBeenCalled();
      expect(getScheduleMock).not.toHaveBeenCalled();
      expect(updateScheduleMock).not.toHaveBeenCalled();
    });
  });
});
