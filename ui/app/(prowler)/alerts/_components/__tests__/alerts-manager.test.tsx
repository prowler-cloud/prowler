import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { isValidElement, type ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ALERT_AGGREGATE_OPS,
  ALERT_TRIGGER_KINDS,
  type AlertRule,
} from "@/app/(prowler)/alerts/_types";

import { AlertsManager } from "../alerts-manager";

const actionMocks = vi.hoisted(() => ({
  deleteAlert: vi.fn(),
  disableAlert: vi.fn(),
  enableAlert: vi.fn(),
  updateAlert: vi.fn(),
}));

const routerMocks = vi.hoisted(() => ({
  refresh: vi.fn(),
  replace: vi.fn(),
  push: vi.fn(),
  currentSearch: "",
}));

const toastMock = vi.hoisted(() => vi.fn());

vi.mock("@/app/(prowler)/alerts/_actions", () => actionMocks);

vi.mock("next/link", () => ({
  default: ({
    children,
    href,
    className,
  }: {
    children: ReactNode;
    href: string;
    className?: string;
  }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

vi.mock("@/lib", () => ({
  cn: (...classes: Array<string | false | null | undefined>) =>
    classes.filter(Boolean).join(" "),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/alerts",
  useRouter: () => routerMocks,
  useSearchParams: () => new URLSearchParams(routerMocks.currentSearch),
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: toastMock }),
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({
    asChild,
    children,
    disabled,
    onClick,
    variant,
  }: {
    asChild?: boolean;
    children: ReactNode;
    disabled?: boolean;
    onClick?: () => void;
    variant?: string;
  }) => {
    if (asChild && isValidElement(children)) {
      return <span data-variant={variant}>{children}</span>;
    }

    return (
      <button
        type="button"
        disabled={disabled}
        onClick={onClick}
        data-variant={variant}
      >
        {children}
      </button>
    );
  },
}));

vi.mock("../alert-form-modal", () => ({
  AlertFormModal: ({
    open,
    editingAlert,
    onOpenChange,
  }: {
    open: boolean;
    editingAlert?: AlertRule | null;
    onOpenChange: (open: boolean) => void;
  }) =>
    open ? (
      <div
        role="dialog"
        aria-label={editingAlert ? "Edit Alert" : "Create Alert"}
      >
        <button type="button" onClick={() => onOpenChange(false)}>
          Close modal
        </button>
        {editingAlert?.attributes.name}
      </div>
    ) : null,
}));

vi.mock("../alerts-empty-state", () => ({
  AlertsEmptyState: () => <div>No alerts</div>,
}));

const makeAlert = (enabled: boolean): AlertRule => ({
  id: enabled ? "enabled-alert" : "disabled-alert",
  type: "alert-rules",
  attributes: {
    name: enabled ? "Enabled alert" : "Disabled alert",
    description: "",
    enabled,
    trigger: ALERT_TRIGGER_KINDS.AFTER_SCAN,
    condition: {
      op: ALERT_AGGREGATE_OPS.ANY,
      filter: { severity: ["critical"] },
    },
    schema_version: 1,
    recipient_emails: [],
    inserted_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
});

const renderManager = (alerts: AlertRule[]) =>
  render(
    <AlertsManager
      alerts={alerts}
      loadError={null}
      providers={[]}
      completedScanIds={[]}
      scanDetails={[]}
      uniqueRegions={[]}
      uniqueServices={[]}
      uniqueResourceTypes={[]}
      uniqueCategories={[]}
      uniqueGroups={[]}
    />,
  );

describe("AlertsManager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    routerMocks.currentSearch = "";
  });

  it("links to Findings from the alerts description", () => {
    // Given
    renderManager([]);

    // When
    const findingsLink = screen.getByRole("link", { name: "Findings" });

    // Then
    expect(findingsLink).toHaveAttribute(
      "href",
      "/findings?filter[muted]=false&filter[status__in]=FAIL",
    );
    expect(findingsLink.closest("[data-variant='link']")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "here." })).toHaveAttribute(
      "href",
      "https://docs.prowler.com/user-guide/tutorials/prowler-app",
    );
    expect(screen.getByText(/get notified when findings match/i)).toBeVisible();
  });

  it("opens the edit modal for an initial editing alert", () => {
    // Given
    const alert = makeAlert(true);

    // When
    render(
      <AlertsManager
        alerts={[alert]}
        loadError={null}
        providers={[]}
        completedScanIds={[]}
        scanDetails={[]}
        uniqueRegions={[]}
        uniqueServices={[]}
        uniqueResourceTypes={[]}
        uniqueCategories={[]}
        uniqueGroups={[]}
        initialEditingAlert={alert}
      />,
    );

    // Then
    expect(
      screen.getByRole("dialog", { name: /edit alert/i }),
    ).toHaveTextContent("Enabled alert");
  });

  it("adds the edit alert id to the URL when opening the edit modal", async () => {
    // Given
    const user = userEvent.setup();
    const alert = makeAlert(true);
    routerMocks.currentSearch = "page=2&filter[enabled]=true";
    renderManager([alert]);

    // When
    await user.click(
      screen.getByRole("button", { name: /actions for enabled alert/i }),
    );
    await user.click(screen.getByRole("menuitem", { name: /edit/i }));

    // Then
    expect(routerMocks.replace).toHaveBeenCalledWith(
      "/alerts?page=2&filter%5Benabled%5D=true&edit=enabled-alert",
      { scroll: false },
    );
    expect(
      screen.getByRole("dialog", { name: /edit alert/i }),
    ).toHaveTextContent("Enabled alert");
  });

  it("removes only the edit alert id from the URL when closing the edit modal", async () => {
    // Given
    const user = userEvent.setup();
    const alert = makeAlert(true);
    routerMocks.currentSearch = "page=2&edit=enabled-alert";
    render(
      <AlertsManager
        alerts={[alert]}
        loadError={null}
        providers={[]}
        completedScanIds={[]}
        scanDetails={[]}
        uniqueRegions={[]}
        uniqueServices={[]}
        uniqueResourceTypes={[]}
        uniqueCategories={[]}
        uniqueGroups={[]}
        initialEditingAlert={alert}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: /close modal/i }));

    // Then
    expect(routerMocks.replace).toHaveBeenCalledWith("/alerts?page=2", {
      scroll: false,
    });
  });

  it("shows a success toast after disabling an alert", async () => {
    // Given
    const user = userEvent.setup();
    const alert = makeAlert(true);
    actionMocks.disableAlert.mockResolvedValue({ data: alert });
    renderManager([alert]);

    // When
    await user.click(
      screen.getByRole("button", { name: /actions for enabled alert/i }),
    );
    await user.click(screen.getByRole("menuitem", { name: /disable/i }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Alert disabled",
        description: "Enabled alert",
      }),
    );
  });

  it("shows a success toast after enabling an alert", async () => {
    // Given
    const user = userEvent.setup();
    const alert = makeAlert(false);
    actionMocks.enableAlert.mockResolvedValue({ data: alert });
    renderManager([alert]);

    // When
    await user.click(
      screen.getByRole("button", { name: /actions for disabled alert/i }),
    );
    await user.click(screen.getByRole("menuitem", { name: /enable/i }));

    // Then
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Alert enabled",
        description: "Disabled alert",
      }),
    );
  });
});
