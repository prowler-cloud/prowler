vi.mock("@/actions/providers/registry-provider", () => ({
  addRegistryProvider: vi.fn(),
}));
vi.mock("@/actions/registry/registry", () => ({
  getInstalledRegistryProviderOptions: vi
    .fn()
    .mockResolvedValue({ status: "access_denied" }),
}));
vi.mock("@/actions/providers/provider-schemas", () => ({
  getProviderSchemas: vi.fn(),
}));
vi.mock("@/actions/providers/dynamic-provider-credentials", () => ({
  saveDynamicProviderCredentials: vi.fn(),
}));
import { Row } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  NODE_KIND,
  ORG_SETUP_PHASE,
  ORG_WIZARD_STEP,
  ORGANIZATION_TYPE,
  type OrganizationType,
} from "@/types/organizations";
import { CONNECTION_CHECK_STATUS } from "@/types/providers";
import {
  PROVIDERS_GROUP_KIND,
  PROVIDERS_ROW_TYPE,
  ProvidersOrganizationRow,
  ProvidersTableRow,
} from "@/types/providers-table";
import type { ScanConfigurationData } from "@/types/scan-configurations";
import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

const {
  checkConnectionProviderMock,
  getProviderConnectionBaselinesMock,
  getScheduleMock,
  getTasksByIdsMock,
  pollConnectionTasksMock,
  pushMock,
  realPollConnectionTasksHolder,
  resolveProviderConnectionStateMock,
  revalidateProvidersMock,
  startProviderConnectionChecksMock,
  testProviderConnectionMock,
  toastMock,
} = vi.hoisted(() => ({
  checkConnectionProviderMock: vi.fn(),
  getProviderConnectionBaselinesMock: vi.fn(),
  getScheduleMock: vi.fn(),
  getTasksByIdsMock: vi.fn(),
  pollConnectionTasksMock: vi.fn(),
  pushMock: vi.fn(),
  // Mutable holder for the real `pollConnectionTasks`, captured once the
  // module mock factory below runs, and read fresh in `beforeEach` since
  // `mockReset: true` clears `pollConnectionTasksMock`'s implementation
  // before every test.
  realPollConnectionTasksHolder: {} as {
    current?: (...args: unknown[]) => unknown;
  },
  resolveProviderConnectionStateMock: vi.fn(),
  revalidateProvidersMock: vi.fn(),
  startProviderConnectionChecksMock: vi.fn(),
  testProviderConnectionMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

vi.mock("@/actions/organizations/organizations", () => ({
  updateOrganizationName: vi.fn(),
}));

vi.mock("@/actions/providers/providers", () => ({
  checkConnectionProvider: checkConnectionProviderMock,
  getProviderConnectionBaselines: getProviderConnectionBaselinesMock,
  revalidateProviders: revalidateProvidersMock,
  startProviderConnectionChecks: startProviderConnectionChecksMock,
}));

vi.mock("@/actions/task/tasks", () => ({
  getTasksByIds: getTasksByIdsMock,
}));

vi.mock("@/actions/schedules", () => ({
  getSchedule: getScheduleMock,
}));

vi.mock("../forms/delete-form", () => ({
  DeleteForm: () => null,
}));

vi.mock("../forms/delete-organization-form", () => ({
  DeleteOrganizationForm: () => null,
}));

vi.mock("../forms/edit-name-form", () => ({
  EditNameForm: () => null,
}));

vi.mock("../scan-config/manage-scan-config-modal", () => ({
  ManageScanConfigModal: ({
    open,
    currentConfigId,
  }: {
    open: boolean;
    currentConfigId: string | null;
  }) =>
    open ? (
      <div
        data-testid="manage-scan-config-modal"
        data-current-config-id={currentConfigId ?? ""}
      />
    ) : null,
}));

vi.mock("@/components/scans/schedule/edit-scan-schedule-modal", () => ({
  EDIT_SCAN_SCHEDULE_STATE: {
    LOADING: "loading",
    LOADED: "loaded",
    ERROR: "error",
  },
  EditScanScheduleModal: ({
    open,
    provider,
    providers,
  }: {
    open: boolean;
    provider?: { providerId: string };
    providers?: { providerId: string }[];
  }) =>
    open ? (
      <div role="dialog" aria-label="Edit Scan Schedule">
        Editing schedule for{" "}
        {providers ? `${providers.length} providers` : provider?.providerId}
      </div>
    ) : null,
}));

vi.mock("@/components/shadcn", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  useToast: () => ({ toast: toastMock }),
}));

vi.mock("@/lib/provider-helpers", () => ({
  resolveProviderConnectionState: resolveProviderConnectionStateMock,
  testProviderConnection: testProviderConnectionMock,
}));

vi.mock(
  "@/components/providers/organizations/org-account-selection.utils",
  async (importOriginal) => {
    const actual =
      await importOriginal<
        typeof import("@/components/providers/organizations/org-account-selection.utils")
      >();
    realPollConnectionTasksHolder.current = actual.pollConnectionTasks as (
      ...args: unknown[]
    ) => unknown;
    return { ...actual, pollConnectionTasks: pollConnectionTasksMock };
  },
);

import { DataTableRowActions } from "./data-table-row-actions";

const createRow = (hasSecret = false) =>
  ({
    original: {
      id: "provider-1",
      rowType: PROVIDERS_ROW_TYPE.PROVIDER,
      type: "providers",
      attributes: {
        provider: "aws",
        uid: "111111111111",
        alias: "AWS App Account",
        status: "completed",
        resources: 0,
        connection: {
          connected: true,
          last_checked_at: "2025-02-13T11:17:00Z",
        },
        scanner_args: {
          only_logs: false,
          excluded_checks: [],
          aws_retries_max_attempts: 3,
        },
        inserted_at: "2025-02-13T11:17:00Z",
        updated_at: "2025-02-13T11:17:00Z",
        created_by: {
          object: "user",
          id: "user-1",
        },
      },
      relationships: {
        secret: {
          data: hasSecret ? { id: "secret-1", type: "secrets" } : null,
        },
        provider_groups: {
          meta: {
            count: 0,
          },
          data: [],
        },
      },
      groupNames: [],
    },
  }) as unknown as Row<ProvidersTableRow>;

// A dynamic provider outside the hardcoded configurable set (read-only in the UI).
const createDynamicRow = (hasSecret = true) =>
  ({
    original: {
      id: "provider-dyn-1",
      rowType: PROVIDERS_ROW_TYPE.PROVIDER,
      type: "providers",
      attributes: {
        provider: "template",
        is_dynamic: true,
        uid: "template-account-0001",
        alias: "Template Plug-in",
        status: "completed",
        resources: 0,
        connection: {
          connected: true,
          last_checked_at: "2025-02-13T11:17:00Z",
        },
        scanner_args: {
          only_logs: false,
          excluded_checks: [],
          aws_retries_max_attempts: 3,
        },
        inserted_at: "2025-02-13T11:17:00Z",
        updated_at: "2025-02-13T11:17:00Z",
        created_by: {
          object: "user",
          id: "user-1",
        },
      },
      relationships: {
        secret: {
          data: hasSecret ? { id: "secret-1", type: "secrets" } : null,
        },
        provider_groups: {
          meta: {
            count: 0,
          },
          data: [],
        },
      },
      groupNames: [],
    },
  }) as unknown as Row<ProvidersTableRow>;

const createOrgRow = () =>
  ({
    original: {
      id: "org-1",
      rowType: PROVIDERS_ROW_TYPE.ORGANIZATION,
      groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION,
      orgType: ORGANIZATION_TYPE.AWS,
      name: "My AWS Organization",
      externalId: "o-abc123def4",
      parentExternalId: null,
      organizationId: "org-1",
      providerCount: 3,
      providerIds: ["provider-child-1", "provider-child-2"],
      subRows: [
        {
          id: "provider-child-1",
          rowType: PROVIDERS_ROW_TYPE.PROVIDER,
          type: "providers",
          attributes: { provider: "aws", uid: "111", alias: null },
          relationships: {
            secret: { data: { id: "secret-1", type: "secrets" } },
          },
        },
        {
          id: "provider-child-2",
          rowType: PROVIDERS_ROW_TYPE.PROVIDER,
          type: "providers",
          attributes: { provider: "aws", uid: "222", alias: null },
          relationships: { secret: { data: null } },
        },
      ],
    },
  }) as unknown as Row<ProvidersTableRow>;

const createOuRow = () =>
  ({
    original: {
      id: "ou-1",
      rowType: PROVIDERS_ROW_TYPE.ORGANIZATION,
      groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION_UNIT,
      orgType: ORGANIZATION_TYPE.AWS,
      kind: NODE_KIND.ORGANIZATIONAL_UNIT,
      name: "Production OU",
      externalId: "ou-abc123",
      parentExternalId: "o-abc123def4",
      organizationId: "org-1",
      providerCount: 2,
      providerIds: ["provider-ou-child-1"],
      subRows: [
        {
          id: "provider-ou-child-1",
          rowType: PROVIDERS_ROW_TYPE.PROVIDER,
          type: "providers",
          attributes: { provider: "aws", uid: "333", alias: null },
          relationships: {
            secret: { data: { id: "secret-2", type: "secrets" } },
          },
        },
      ],
    },
  }) as unknown as Row<ProvidersTableRow>;

const scanConfig: ScanConfigurationData = {
  type: "scan-configurations",
  id: "config-1",
  attributes: {
    inserted_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    name: "Strict AWS",
    configuration: {},
    providers: ["provider-1"],
  },
};

describe("DataTableRowActions", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  beforeEach(() => {
    // `mockReset: true` (vitest.config.ts) clears this before every test, so
    // the real implementation is the default and tests only override it when
    // they need to simulate an exhausted poll.
    pollConnectionTasksMock.mockImplementation((...args: unknown[]) =>
      realPollConnectionTasksHolder.current?.(...args),
    );
    getScheduleMock.mockResolvedValue({
      data: {
        type: "schedules",
        id: "provider-1",
        attributes: { scan_hour: null },
        relationships: {
          provider: { data: { type: "providers", id: "provider-1" } },
        },
      },
    });
    getProviderConnectionBaselinesMock.mockResolvedValue({});
  });

  it("renders Add Credentials for provider rows without credentials", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createRow(false)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then
    expect(screen.getByText("Edit Provider Alias")).toBeInTheDocument();
    // Advanced schedule editing is gated to Prowler Cloud subscribed accounts.
    expect(screen.queryByText("Edit Scan Schedule")).not.toBeInTheDocument();
    expect(screen.getByText("Add Credentials")).toBeInTheDocument();
    expect(screen.getByText("Test Connection")).toBeInTheDocument();
    expect(screen.getByText("Delete Provider")).toBeInTheDocument();
    expect(screen.queryByText("Update Credentials")).not.toBeInTheDocument();
  });

  it("allows credential editing and operational actions for a dynamic provider", async () => {
    // Given a dynamic provider outside the configurable set, with the advanced
    // schedule capability enabled (so Edit Scan Schedule can show).
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createDynamicRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
        capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then — rename and delete are backend-generic, so they stay available
    expect(screen.getByText("Edit Provider Alias")).toBeInTheDocument();
    expect(screen.getByText("Delete Provider")).toBeInTheDocument();
    // ...operational actions stay available too
    expect(screen.getByText("Test Connection")).toBeInTheDocument();
    expect(screen.getByText("View Scan Jobs")).toBeInTheDocument();
    expect(screen.getByText("Edit Scan Schedule")).toBeInTheDocument();
    // Existing dynamic accounts use the same wizard with schema-based credentials.
    expect(screen.queryByText("Add Credentials")).not.toBeInTheDocument();
    expect(screen.getByText("Update Credentials")).toBeInTheDocument();
  });

  it("navigates to the provider-filtered scan jobs from View Scan Jobs", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("View Scan Jobs"));

    // Then: navigates with the key the scans filter bar binds to
    // (provider__in, by id), URL-encoded, so the provider is pre-selected.
    expect(pushMock).toHaveBeenCalledWith(
      "/scans?filter%5Bprovider__in%5D=provider-1",
    );
  });

  it("links to scan jobs by provider id even when the uid contains unsafe chars", async () => {
    // Given a GitHub provider whose UID is a URL with unsafe chars.
    const user = userEvent.setup();
    const row = createRow(true);
    (
      row.original as unknown as { attributes: { uid: string } }
    ).attributes.uid = "https://github.com/prowler-cloud/prowler";

    render(
      <DataTableRowActions
        row={row}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("View Scan Jobs"));

    // Then the link carries the provider id, never the raw uid.
    expect(pushMock).toHaveBeenCalledWith(
      "/scans?filter%5Bprovider__in%5D=provider-1",
    );
  });

  it("opens Edit Scan Schedule for Prowler Cloud subscribed provider rows", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();

    render(
      <DataTableRowActions
        row={createRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("Edit Scan Schedule"));

    // Then
    expect(
      screen.getByRole("dialog", { name: /edit scan schedule/i }),
    ).toHaveTextContent("Editing schedule for provider-1");
  });

  it("hides Edit Scan Schedule for manual-only Cloud provider rows", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();

    render(
      <DataTableRowActions
        row={createRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
        capability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then
    expect(screen.queryByText("Edit Scan Schedule")).not.toBeInTheDocument();
  });

  it("hides Edit Scan Schedule for blocked Cloud provider rows", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();

    render(
      <DataTableRowActions
        row={createRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
        capability={SCAN_SCHEDULE_CAPABILITY.BLOCKED}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then
    expect(screen.queryByText("Edit Scan Schedule")).not.toBeInTheDocument();
  });

  it("opens scan config management with the precomputed current config id", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();

    render(
      <DataTableRowActions
        row={createRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
        scanConfigs={[scanConfig]}
        currentScanConfigId="config-1"
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("Edit Scan Configuration"));

    // Then
    expect(screen.getByTestId("manage-scan-config-modal")).toHaveAttribute(
      "data-current-config-id",
      "config-1",
    );
  });

  it("shows scan config management as unavailable when scan configs failed to load", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();

    render(
      <DataTableRowActions
        row={createRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
        scanConfigStatus="unavailable"
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then
    const item = screen
      .getByText("Scan Configuration unavailable")
      .closest("[role='menuitem']");
    expect(item).toHaveAttribute("aria-disabled", "true");
  });

  it("hides Edit Scan Configuration for dynamic providers in Prowler Cloud", async () => {
    // Given a dynamic provider in a Cloud tenant with scan configs available.
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    const user = userEvent.setup();

    render(
      <DataTableRowActions
        row={createDynamicRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
        scanConfigs={[]}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then — dynamic providers can't use a Scan Configuration, so the action is
    // absent entirely, not merely shown as "unavailable".
    expect(
      screen.queryByText("Edit Scan Configuration"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("Scan Configuration unavailable"),
    ).not.toBeInTheDocument();
  });

  it("renders Update Credentials for provider rows with credentials", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then
    expect(screen.getByText("Update Credentials")).toBeInTheDocument();
    expect(screen.queryByText("Add Credentials")).not.toBeInTheDocument();
  });

  it("renders all 4 organization actions for org rows", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    expect(screen.getByText("Edit Organization Name")).toBeInTheDocument();
    expect(screen.getByText("Update Credentials")).toBeInTheDocument();
    // 1 of 2 child providers has a secret
    expect(screen.getByText("Test Connections (1)")).toBeInTheDocument();
    expect(screen.getByText("Delete Organization")).toBeInTheDocument();
  });

  it("opens Edit Scan Schedule for AWS organization rows", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
        capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
      />,
    );

    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("Edit Scan Schedule"));

    expect(
      screen.getByRole("dialog", { name: /edit scan schedule/i }),
    ).toHaveTextContent("Editing schedule for 2 providers");
  });

  it("renders Delete Organization with destructive styling for org rows", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    const deleteItem = screen.getByText("Delete Organization");
    // Destructive items are rendered with error text color
    const menuItem = deleteItem.closest("[role='menuitem']");
    expect(menuItem).toBeInTheDocument();
    expect(menuItem).toHaveClass("text-text-error-primary");
  });

  it("renders only Test Connections and Delete for OU rows", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOuRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    expect(screen.getByText("Test Connections (1)")).toBeInTheDocument();
    // Node action copy follows the node's kind.
    expect(screen.getByText("Delete Organizational Unit")).toBeInTheDocument();
  });

  it("shows selected provider count in Test Connections when org row has active selection", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={true}
        isRowSelected={false}
        testableProviderIds={["provider-child-1", "provider-standalone"]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    // Should show count of selected testable providers (2), not all org children (1)
    expect(screen.getByText("Test Connections (2)")).toBeInTheDocument();
    expect(screen.queryByText("Test Connections (1)")).not.toBeInTheDocument();
  });

  it("tests every selected provider in one dispatch, not one call each", async () => {
    // Given — Next's action queue serializes a per-provider loop, so the batch has
    // to leave in a single action.
    const user = userEvent.setup();
    const testableProviderIds = ["provider-child-1", "provider-standalone"];
    startProviderConnectionChecksMock.mockResolvedValue({
      "provider-child-1": { taskId: "task-1" },
      "provider-standalone": { taskId: "task-2" },
    });
    getTasksByIdsMock.mockResolvedValue({
      "task-1": {
        data: {
          attributes: { state: "completed", result: { connected: true } },
        },
      },
      "task-2": {
        data: {
          attributes: { state: "completed", result: { connected: true } },
        },
      },
    });

    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={true}
        isRowSelected={false}
        testableProviderIds={testableProviderIds}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("Test Connections (2)"));

    // Then — one dispatch for the batch, one batched read, one revalidation.
    await vi.waitFor(() =>
      expect(revalidateProvidersMock).toHaveBeenCalledTimes(1),
    );
    expect(startProviderConnectionChecksMock).toHaveBeenCalledTimes(1);
    expect(startProviderConnectionChecksMock).toHaveBeenCalledWith(
      testableProviderIds,
    );
    expect(getTasksByIdsMock).toHaveBeenCalledTimes(1);
    expect(getTasksByIdsMock).toHaveBeenCalledWith(["task-1", "task-2"]);
    expect(checkConnectionProviderMock).not.toHaveBeenCalled();
  });

  it("falls back to the provider's persisted state for a task still pending once the bulk wait is exhausted", async () => {
    // Given: the batch poll exhausts its retries for both tasks; the component
    // must re-read each provider's connection state instead of reporting a
    // flat timeout.
    const user = userEvent.setup();
    const testableProviderIds = ["provider-child-1", "provider-standalone"];
    startProviderConnectionChecksMock.mockResolvedValue({
      "provider-child-1": { taskId: "task-1" },
      "provider-standalone": { taskId: "task-2" },
    });
    // The baseline read before dispatch: one provider has a prior stored check,
    // the other has never been checked.
    getProviderConnectionBaselinesMock.mockResolvedValue({
      "provider-child-1": "2025-01-01T00:00:00Z",
      "provider-standalone": null,
    });
    pollConnectionTasksMock.mockImplementation(
      async (taskIds: string[], { onSettled, resolveExhausted }) => {
        for (const taskId of taskIds) {
          const resolved = resolveExhausted
            ? await resolveExhausted(taskId)
            : null;
          onSettled(
            taskId,
            resolved ?? {
              status: CONNECTION_CHECK_STATUS.FAILED,
              error: "Connection test timed out.",
            },
          );
        }
      },
    );
    resolveProviderConnectionStateMock.mockImplementation(
      async (providerId: string) =>
        providerId === "provider-standalone"
          ? { status: CONNECTION_CHECK_STATUS.SUCCESS, error: null }
          : {
              status: CONNECTION_CHECK_STATUS.FAILED,
              error: "Connection was not confirmed. Test the connection again.",
            },
    );

    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={true}
        isRowSelected={false}
        testableProviderIds={testableProviderIds}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("Test Connections (2)"));

    // Then: each pending task is resolved from the provider's own record, using
    // the baseline captured for that specific provider before dispatch.
    await vi.waitFor(() =>
      expect(revalidateProvidersMock).toHaveBeenCalledTimes(1),
    );
    expect(getProviderConnectionBaselinesMock).toHaveBeenCalledWith(
      testableProviderIds,
    );
    expect(resolveProviderConnectionStateMock).toHaveBeenCalledWith(
      "provider-child-1",
      "2025-01-01T00:00:00Z",
    );
    expect(resolveProviderConnectionStateMock).toHaveBeenCalledWith(
      "provider-standalone",
      null,
    );
  });

  it("shows a neutral toast, not a failure, when a single test is still running past the wait", async () => {
    // Given: the exhausted single-provider test cannot confirm an outcome yet.
    const user = userEvent.setup();
    testProviderConnectionMock.mockResolvedValue({
      status: CONNECTION_CHECK_STATUS.PENDING,
      error:
        "The connection test is still running. Refresh in a moment to see the result.",
    });

    render(
      <DataTableRowActions
        row={createRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("Test Connection"));

    // Then: no destructive toast for a check that is merely still running.
    await vi.waitFor(() => expect(toastMock).toHaveBeenCalledTimes(1));
    expect(toastMock).toHaveBeenCalledWith(
      expect.not.objectContaining({ variant: "destructive" }),
    );
    expect(toastMock.mock.calls[0][0].title).not.toMatch(/failed/i);
  });

  it("does not count a still-running bulk result as failed", async () => {
    // Given: one provider settles successfully, the other is still running
    // once the bulk wait is exhausted.
    const user = userEvent.setup();
    const testableProviderIds = ["provider-child-1", "provider-standalone"];
    startProviderConnectionChecksMock.mockResolvedValue({
      "provider-child-1": { taskId: "task-1" },
      "provider-standalone": { taskId: "task-2" },
    });
    pollConnectionTasksMock.mockImplementation(
      async (taskIds: string[], { onSettled, resolveExhausted }) => {
        for (const taskId of taskIds) {
          const resolved = resolveExhausted
            ? await resolveExhausted(taskId)
            : null;
          onSettled(
            taskId,
            resolved ?? {
              status: CONNECTION_CHECK_STATUS.FAILED,
              error: "Connection test timed out.",
            },
          );
        }
      },
    );
    resolveProviderConnectionStateMock.mockImplementation(
      async (providerId: string) =>
        providerId === "provider-standalone"
          ? { status: CONNECTION_CHECK_STATUS.SUCCESS, error: null }
          : {
              status: CONNECTION_CHECK_STATUS.PENDING,
              error: "The connection test is still running.",
            },
    );

    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={true}
        isRowSelected={false}
        testableProviderIds={testableProviderIds}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("Test Connections (2)"));

    // Then: not styled as a failure — no destructive toast.
    await vi.waitFor(() => expect(toastMock).toHaveBeenCalledTimes(1));
    expect(toastMock).toHaveBeenCalledWith(
      expect.not.objectContaining({ variant: "destructive" }),
    );
  });

  it("shows selected provider count in Test Connections when OU row has active selection", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOuRow()}
        hasSelection={true}
        isRowSelected={false}
        testableProviderIds={["provider-ou-child-1", "provider-standalone"]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    // Should show count of selected testable providers (2), not all OU children (1)
    expect(screen.getByText("Test Connections (2)")).toBeInTheDocument();
    expect(screen.queryByText("Test Connections (1)")).not.toBeInTheDocument();
  });

  it("shows bulk Edit Scan Schedule next to Test Connection for selected rows", async () => {
    // Given
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={true}
        isRowSelected={true}
        testableProviderIds={["provider-child-1", "provider-standalone"]}
        selectedScheduleProviderIds={[
          "provider-child-1",
          "provider-child-2",
          "provider-standalone",
        ]}
        selectedScheduleProviders={[
          {
            providerId: "provider-child-1",
            providerType: "aws",
            providerUid: "111",
            providerAlias: null,
          },
          {
            providerId: "provider-standalone",
            providerType: "aws",
            providerUid: "999",
            providerAlias: "Standalone",
          },
        ]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
        capability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then
    expect(screen.getByText("Edit Scan Schedule (3)")).toBeInTheDocument();
    expect(screen.getByText("Test Connection (2)")).toBeInTheDocument();
  });

  it("does NOT render Edit Organization Name or Update Credentials for OU rows", async () => {
    const user = userEvent.setup();
    render(
      <DataTableRowActions
        row={createOuRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button"));

    expect(
      screen.queryByText("Edit Organization Name"),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Update Credentials")).not.toBeInTheDocument();
  });

  it("opens the shared provider wizard when provider credentials action is selected", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenProviderWizard = vi.fn();

    render(
      <DataTableRowActions
        row={createRow(true)}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={onOpenProviderWizard}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("Update Credentials"));

    // Then
    expect(onOpenProviderWizard).toHaveBeenCalledWith({
      providerId: "provider-1",
      providerType: "aws",
      providerUid: "111111111111",
      providerAlias: "AWS App Account",
      secretId: "secret-1",
      mode: "update",
    });
  });

  it("opens the shared organization wizard when org credentials action is selected", async () => {
    // Given
    const user = userEvent.setup();
    const onOpenOrganizationWizard = vi.fn();

    render(
      <DataTableRowActions
        row={createOrgRow()}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={onOpenOrganizationWizard}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));
    await user.click(screen.getByText("Update Credentials"));

    // Then
    expect(onOpenOrganizationWizard).toHaveBeenCalledWith({
      organizationType: ORGANIZATION_TYPE.AWS,
      organizationId: "org-1",
      organizationName: "My AWS Organization",
      externalId: "o-abc123def4",
      targetStep: ORG_WIZARD_STEP.SETUP,
      targetPhase: ORG_SETUP_PHASE.ACCESS,
      intent: "edit-credentials",
    });
  });

  it("hides Update Credentials for an organization type without an onboarding flow", async () => {
    // Given: an organization type the wizard cannot onboard (display-only).
    // Every `ORGANIZATION_TYPE` is onboardable now, so the value comes from
    // outside the enum.
    const user = userEvent.setup();
    const row = createOrgRow();
    (row.original as ProvidersOrganizationRow).orgType =
      "oraclecloud" as OrganizationType;

    render(
      <DataTableRowActions
        row={row}
        hasSelection={false}
        isRowSelected={false}
        testableProviderIds={[]}
        onClearSelection={vi.fn()}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button"));

    // Then: the name edit stays (a plain PATCH), the wizard re-entry is gone.
    expect(screen.getByText("Edit Organization Name")).toBeInTheDocument();
    expect(screen.queryByText("Update Credentials")).not.toBeInTheDocument();
  });
});
