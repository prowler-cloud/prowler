import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps, ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

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
}));

vi.mock("@/app/(prowler)/alerts/_components/alert-form-modal", () => ({
  AlertFormModal: ({
    open,
    initialFindingsFilters,
    selectedFindingsFilterChips,
    defaultName,
    onSubmit,
  }: {
    open: boolean;
    initialFindingsFilters?: Record<string, string | string[]>;
    selectedFindingsFilterChips?: Array<{
      label: string;
      displayValue?: string;
      value: string;
    }>;
    defaultName?: string;
    onSubmit: (
      values: AlertFormValues,
      advancedCondition: AlertCondition | null,
    ) => Promise<AlertFormSubmitResult>;
  }) =>
    open ? (
      <div role="dialog" aria-label="Create alert">
        <output data-testid="initial-filters">
          {JSON.stringify(initialFindingsFilters)}
        </output>
        <output data-testid="selected-filter-chips">
          {(selectedFindingsFilterChips ?? [])
            .map((chip) => `${chip.label}:${chip.displayValue ?? chip.value}`)
            .join("|")}
        </output>
        <button
          type="button"
          onClick={() =>
            onSubmit(
              {
                name: defaultName ?? "Findings filter alert",
                description: "",
                method: "email",
                frequency: "after_scan",
                filterGroup: { operator: "all", children: [] },
                severities: [],
                deltas: [],
                providerTypes: [],
                providerIds: [],
                checkIds: [],
                categories: [],
                regions: [],
                services: [],
                resourceGroups: [],
                findingGroupIds: [],
                resourceTypes: [],
                recipientEmails: ["security@example.com"],
                enabled: true,
              },
              null,
            )
          }
        >
          Submit mock alert
        </button>
      </div>
    ) : null,
}));

import { SeedFromFindingsButton } from "../seed-from-findings-button";

describe("SeedFromFindingsButton", () => {
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
  });

  it("should open the modal in Findings and keep unsupported filters out of the payload seed", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <SeedFromFindingsButton
        filterBag={{
          "filter[status__in]": "FAIL",
          "filter[muted]": "false",
          "filter[scan__in]": "11111111-1111-1111-1111-111111111111",
          "filter[severity__in]": "critical,high",
        }}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /Create Alert/i }));

    // Then
    expect(screen.getByRole("dialog", { name: /create alert/i })).toBeVisible();
    expect(routerMocks.push).not.toHaveBeenCalled();
    expect(screen.getByTestId("selected-filter-chips")).toHaveTextContent(
      /status:fail/i,
    );
    expect(screen.getByTestId("selected-filter-chips")).toHaveTextContent(
      /muted:false/i,
    );
    expect(screen.getByTestId("initial-filters")).toHaveTextContent(
      "filter[severity__in]",
    );
    expect(screen.getByTestId("initial-filters")).not.toHaveTextContent(
      "filter[status__in]",
    );
    expect(screen.getByTestId("initial-filters")).not.toHaveTextContent(
      "filter[muted]",
    );
    expect(screen.getByTestId("initial-filters")).not.toHaveTextContent(
      "filter[scan__in]",
    );
  });

  it("should create the alert through the existing alert action from the modal", async () => {
    // Given
    const user = userEvent.setup();
    actionMocks.createAlert.mockResolvedValue({
      ok: true,
      data: {
        data: {
          id: "alert-1",
          attributes: { name: "Findings filter alert" },
        },
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
    actionMocks.createAlert.mockResolvedValue({
      ok: true,
      data: {
        data: {
          id: "alert-1",
          attributes: { name: "Findings filter alert" },
        },
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
});
