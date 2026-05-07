import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps, ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AlertCondition } from "@/app/(prowler)/alerts/_types";
import type {
  AlertFormSubmitResult,
  AlertFormValues,
} from "@/app/(prowler)/alerts/_types/alert-form";

const routerMocks = vi.hoisted(() => ({
  push: vi.fn(),
  refresh: vi.fn(),
}));

const actionMocks = vi.hoisted(() => ({
  createAlert: vi.fn(),
  seedAlertRule: vi.fn(),
}));

const toastMock = vi.hoisted(() => vi.fn());

vi.mock("next/navigation", () => ({
  useRouter: () => routerMocks,
}));

vi.mock("@/components/ui", () => ({
  ToastAction: ({
    asChild,
    children,
    ...props
  }: ComponentProps<"button"> & {
    asChild?: boolean;
    children?: ReactNode;
  }) => (asChild ? children : <button {...props}>{children}</button>),
  useToast: () => ({ toast: toastMock }),
}));

vi.mock("@/app/(prowler)/alerts/_actions", () => ({
  createAlert: actionMocks.createAlert,
  seedAlertRule: actionMocks.seedAlertRule,
}));

vi.mock("@/app/(prowler)/alerts/_components/alert-form-modal", () => ({
  AlertFormModal: ({
    open,
    seededCondition,
    selectedFindingsFilterChips,
    defaultName,
    onSubmit,
  }: {
    open: boolean;
    seededCondition?: AlertCondition | null;
    selectedFindingsFilterChips?: Array<{
      label: string;
      displayValue?: string;
      value: string;
    }>;
    defaultName?: string;
    onSubmit: (values: AlertFormValues) => Promise<AlertFormSubmitResult>;
  }) =>
    open ? (
      <div role="dialog" aria-label="Create alert">
        <output data-testid="seeded-condition">
          {JSON.stringify(seededCondition)}
        </output>
        <output data-testid="selected-filter-chips">
          {(selectedFindingsFilterChips ?? [])
            .map((chip) => `${chip.label}:${chip.displayValue ?? chip.value}`)
            .join("|")}
        </output>
        <button
          type="button"
          onClick={() =>
            onSubmit({
              name: defaultName ?? "Findings filter alert",
              description: "",
              method: "email",
              frequency: "after_scan",
              condition: seededCondition ?? {
                op: "any",
                filter: { severity: ["critical"] },
              },
              recipientEmails: ["security@example.com"],
              enabled: true,
            })
          }
        >
          Submit mock alert
        </button>
      </div>
    ) : null,
}));

import { SeedFromFindingsButton } from "../seed-from-findings-button";

describe("SeedFromFindingsButton", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("should explain why creating an alert is disabled when no real filters are applied", async () => {
    // Given
    const user = userEvent.setup();
    render(<SeedFromFindingsButton filterBag={{ sort: "-inserted_at" }} />);

    // When
    const button = screen.getByRole("button", {
      name: /Create Alert/i,
    });
    const tooltipTrigger = button.parentElement;
    expect(tooltipTrigger).not.toBeNull();
    await user.hover(tooltipTrigger as HTMLElement);

    // Then
    expect(button).toBeDisabled();
    expect(
      await screen.findAllByText(/at least one findings filter/i),
    ).not.toHaveLength(0);
  });

  it("should enable creation from the first real filter, including unsupported backend filters", () => {
    // Given / When
    render(
      <SeedFromFindingsButton
        filterBag={{
          "filter[status__in]": "FAIL",
          "filter[muted]": "false",
          "filter[scan__in]": "11111111-1111-1111-1111-111111111111",
        }}
      />,
    );

    // Then
    expect(
      screen.getByRole("button", { name: /Create Alert/i }),
    ).not.toBeDisabled();
    expect(screen.getByRole("button", { name: /Create Alert/i })).toHaveClass(
      "h-10",
    );
  });

  it("should add all severities when Findings only has non-portable default filters", async () => {
    // Given
    const user = userEvent.setup();
    const seededCondition: AlertCondition = {
      op: "any",
      filter: {
        severity: ["critical", "high", "medium", "low", "informational"],
      },
    };
    actionMocks.seedAlertRule.mockResolvedValue({
      data: {
        attributes: {
          condition: seededCondition,
          schema_version: 1,
          warnings: [],
        },
      },
    });
    const filterBag = {
      "filter[status__in]": "FAIL",
      "filter[muted]": "false",
      "filter[scan__in]": "11111111-1111-1111-1111-111111111111",
    };
    render(<SeedFromFindingsButton filterBag={filterBag} />);

    // When
    await user.click(screen.getByRole("button", { name: /Create Alert/i }));

    // Then
    await waitFor(() =>
      expect(actionMocks.seedAlertRule).toHaveBeenCalledWith({
        ...filterBag,
        "filter[severity__in]": [
          "critical",
          "high",
          "medium",
          "low",
          "informational",
        ],
      }),
    );
    expect(screen.getByRole("dialog", { name: /create alert/i })).toBeVisible();
    expect(screen.getByTestId("seeded-condition")).toHaveTextContent(
      "severity",
    );
  });

  it("should seed from the full Findings filter bag before opening the modal", async () => {
    // Given
    const user = userEvent.setup();
    const seededCondition: AlertCondition = {
      op: "any",
      filter: { severity: ["critical", "high"] },
    };
    actionMocks.seedAlertRule.mockResolvedValue({
      data: {
        attributes: {
          condition: seededCondition,
          schema_version: 1,
          warnings: [],
        },
      },
    });
    const filterBag = {
      "filter[status__in]": "FAIL",
      "filter[muted]": "false",
      "filter[scan__in]": "11111111-1111-1111-1111-111111111111",
      "filter[severity__in]": "critical,high",
    };
    render(<SeedFromFindingsButton filterBag={filterBag} />);

    // When
    await user.click(screen.getByRole("button", { name: /Create Alert/i }));

    // Then
    await waitFor(() =>
      expect(actionMocks.seedAlertRule).toHaveBeenCalledWith(filterBag),
    );
    expect(screen.getByRole("dialog", { name: /create alert/i })).toBeVisible();
    expect(routerMocks.push).not.toHaveBeenCalled();
    expect(screen.getByTestId("selected-filter-chips")).toHaveTextContent(
      /severity:\+2/i,
    );
    expect(screen.getByTestId("seeded-condition")).toHaveTextContent(
      "severity",
    );
    expect(screen.getByTestId("selected-filter-chips")).not.toHaveTextContent(
      /status/i,
    );
  });

  it("should create the alert through the existing alert action from the modal", async () => {
    // Given
    const user = userEvent.setup();
    const seededCondition: AlertCondition = {
      op: "any",
      filter: { severity: ["critical"] },
    };
    actionMocks.seedAlertRule.mockResolvedValue({
      data: {
        attributes: {
          condition: seededCondition,
          schema_version: 1,
          warnings: [],
        },
      },
    });
    actionMocks.createAlert.mockResolvedValue({
      data: {
        id: "alert-1",
        attributes: { name: "Findings filter alert" },
      },
    });
    render(
      <SeedFromFindingsButton
        filterBag={{ "filter[severity__in]": "critical" }}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /Create Alert/i }));
    await user.click(
      screen.getByRole("button", { name: /submit mock alert/i }),
    );

    // Then
    await waitFor(() =>
      expect(actionMocks.createAlert).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "Findings filter alert",
          trigger: "after_scan",
          condition: seededCondition,
          recipientEmails: ["security@example.com"],
        }),
      ),
    );
    expect(routerMocks.refresh).toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Alert created",
        action: expect.anything(),
      }),
    );
  });

  it("should add a toast action to navigate to alerts after creating an alert", async () => {
    // Given
    const user = userEvent.setup();
    actionMocks.seedAlertRule.mockResolvedValue({
      data: {
        attributes: {
          condition: { op: "any", filter: { severity: ["critical"] } },
          schema_version: 1,
          warnings: [],
        },
      },
    });
    actionMocks.createAlert.mockResolvedValue({
      data: {
        id: "alert-1",
        attributes: { name: "Findings filter alert" },
      },
    });
    render(
      <SeedFromFindingsButton
        filterBag={{ "filter[severity__in]": "critical" }}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /Create Alert/i }));
    await user.click(
      screen.getByRole("button", { name: /submit mock alert/i }),
    );

    // Then
    await waitFor(() => expect(toastMock).toHaveBeenCalled());
    const toastAction = toastMock.mock.calls[0][0].action;
    render(toastAction);
    expect(screen.getByRole("link", { name: /view alerts/i })).toHaveAttribute(
      "href",
      "/alerts",
    );
  });

  it("should show a toast and keep the modal closed when seed fails", async () => {
    // Given
    const user = userEvent.setup();
    actionMocks.seedAlertRule.mockResolvedValue({
      error: "invalid_shape",
    });
    render(
      <SeedFromFindingsButton
        filterBag={{ "filter[severity__in]": "critical" }}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /Create Alert/i }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          title: "Alert seed failed",
        }),
      ),
    );
    expect(
      screen.queryByRole("dialog", { name: /create alert/i }),
    ).not.toBeInTheDocument();
  });

  it("should render disabled as a Cloud-only feature in OSS", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <SeedFromFindingsButton
        filterBag={{ "filter[severity__in]": "critical" }}
        isCloudEnabled={false}
      />,
    );

    // When
    const button = screen.getByRole("button", { name: /Create Alert/i });
    await user.hover(button.parentElement as HTMLElement);

    // Then
    expect(button).toBeDisabled();
    expect(screen.getByText("Prowler Cloud")).toBeVisible();
    expect(
      await screen.findAllByText(/available in prowler cloud/i),
    ).not.toHaveLength(0);
    expect(actionMocks.seedAlertRule).not.toHaveBeenCalled();
  });
});
