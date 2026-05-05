import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
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
}));

const toastMock = vi.hoisted(() => vi.fn());

vi.mock("@/app/(prowler)/alerts/_actions", () => actionMocks);

vi.mock("@/lib", () => ({
  cn: (...classes: Array<string | false | null | undefined>) =>
    classes.filter(Boolean).join(" "),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/alerts",
  useRouter: () => routerMocks,
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: toastMock }),
}));

vi.mock("@/components/shadcn", () => ({
  Button: ({
    children,
    disabled,
    onClick,
    variant,
  }: {
    children: ReactNode;
    disabled?: boolean;
    onClick?: () => void;
    variant?: string;
  }) => (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      data-variant={variant}
    >
      {children}
    </button>
  ),
}));

vi.mock("../alert-form-modal", () => ({
  AlertFormModal: () => null,
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
  });

  it("shows a success toast after disabling an alert", async () => {
    // Given
    const user = userEvent.setup();
    const alert = makeAlert(true);
    actionMocks.disableAlert.mockResolvedValue({
      ok: true,
      data: { data: alert },
    });
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
    actionMocks.enableAlert.mockResolvedValue({
      ok: true,
      data: { data: alert },
    });
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
