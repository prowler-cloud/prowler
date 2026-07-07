import { Row } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ORG_SETUP_PHASE, ORG_WIZARD_STEP } from "@/types/organizations";
import {
  PROVIDERS_GROUP_KIND,
  PROVIDERS_ROW_TYPE,
  ProvidersTableRow,
} from "@/types/providers-table";
import type { ScanConfigurationData } from "@/types/scan-configurations";
import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

const { checkConnectionProviderMock, getScheduleMock, pushMock } = vi.hoisted(
  () => ({
    checkConnectionProviderMock: vi.fn(),
    getScheduleMock: vi.fn(),
    pushMock: vi.fn(),
  }),
);

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

vi.mock("@/actions/organizations/organizations", () => ({
  updateOrganizationName: vi.fn(),
}));

vi.mock("@/actions/providers/providers", () => ({
  checkConnectionProvider: checkConnectionProviderMock,
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
  useToast: () => ({ toast: vi.fn() }),
}));

vi.mock("@/lib/provider-helpers", () => ({
  testProviderConnection: vi.fn(),
}));

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

const createOrgRow = () =>
  ({
    original: {
      id: "org-1",
      rowType: PROVIDERS_ROW_TYPE.ORGANIZATION,
      groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION,
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
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
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
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
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
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
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
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
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
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
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
    expect(screen.getByText("Delete Organization Unit")).toBeInTheDocument();
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
      organizationId: "org-1",
      organizationName: "My AWS Organization",
      externalId: "o-abc123def4",
      targetStep: ORG_WIZARD_STEP.SETUP,
      targetPhase: ORG_SETUP_PHASE.ACCESS,
      intent: "edit-credentials",
    });
  });
});
