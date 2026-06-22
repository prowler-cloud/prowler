import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { MetaDataProps } from "@/types";
import {
  PROVIDERS_GROUP_KIND,
  PROVIDERS_ROW_TYPE,
  type ProvidersTableRow,
} from "@/types/providers-table";
import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

const { dataTableMockState, getColumnProvidersMock, getScheduleMock } =
  vi.hoisted(() => ({
    dataTableMockState: {
      nextSelection: {} as Record<string, boolean>,
    },
    getColumnProvidersMock: vi.fn((..._args: unknown[]) => []),
    getScheduleMock: vi.fn(),
  }));

vi.mock("@/actions/schedules", () => ({
  getSchedule: getScheduleMock,
}));

vi.mock("@/components/scans/schedule/edit-scan-schedule-modal", () => ({
  EDIT_SCAN_SCHEDULE_STATE: {
    LOADING: "loading",
    LOADED: "loaded",
    ERROR: "error",
  },
  EditScanScheduleModal: ({
    open,
    providers = [],
    providerIds = [],
    onSaved,
  }: {
    open: boolean;
    providers?: Array<{ providerId: string }>;
    providerIds?: string[];
    onSaved?: () => void;
  }) =>
    open ? (
      <div role="dialog" aria-label="Edit Scan Schedule">
        <output data-testid="schedule-provider-ids">
          {providerIds.join(",")}
        </output>
        <output data-testid="schedule-visible-providers">
          {providers.map((provider) => provider.providerId).join(",")}
        </output>
        <button type="button" onClick={onSaved}>
          Simulate save
        </button>
      </div>
    ) : null,
}));

vi.mock("@/components/ui/table", () => ({
  DataTable: ({
    onRowSelectionChange,
    toolbarRightContent,
  }: {
    onRowSelectionChange?: (selection: Record<string, boolean>) => void;
    toolbarRightContent?: React.ReactNode;
  }) => (
    <div data-testid="providers-data-table">
      <button
        type="button"
        onClick={() => onRowSelectionChange?.(dataTableMockState.nextSelection)}
      >
        Apply selection
      </button>
      <div data-testid="providers-toolbar">{toolbarRightContent}</div>
    </div>
  ),
}));

vi.mock("./table", () => ({
  getColumnProviders: (...args: unknown[]) => getColumnProvidersMock(...args),
}));

import {
  computeSelectedScheduleProviders,
  ProvidersAccountsTable,
} from "./providers-accounts-table";

const metadata: MetaDataProps = {
  pagination: { page: 1, pages: 1, count: 0, itemsPerPage: [10] },
  version: "latest",
};

const scheduleResponse = {
  data: {
    type: "schedules",
    id: "provider-1",
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
      provider: { data: { type: "providers", id: "provider-1" } },
    },
  },
};

const createProviderRow = (
  id: string,
  uid = id,
  alias: string | null = id,
): ProvidersTableRow =>
  ({
    id,
    rowType: PROVIDERS_ROW_TYPE.PROVIDER,
    type: "providers",
    attributes: {
      provider: "aws",
      uid,
      alias,
      status: "completed",
      resources: 0,
      connection: {
        connected: true,
        last_checked_at: "2026-01-01T00:00:00Z",
      },
      scanner_args: {
        only_logs: false,
        excluded_checks: [],
        aws_retries_max_attempts: 3,
      },
      inserted_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      created_by: {
        object: "user",
        id: "user-1",
      },
    },
    relationships: {
      secret: { data: { id: `secret-${id}`, type: "secrets" } },
      provider_groups: { meta: { count: 0 }, data: [] },
    },
    groupNames: [],
    hasSchedule: false,
  }) as ProvidersTableRow;

const providerOne = createProviderRow("provider-1", "111111111111", "Prod");
const providerTwo = createProviderRow("provider-2", "222222222222", "Stage");
const providerThree = createProviderRow("provider-3", "333333333333", "Dev");

const organizationRow: ProvidersTableRow = {
  id: "org-1",
  rowType: PROVIDERS_ROW_TYPE.ORGANIZATION,
  groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION,
  name: "My AWS Organization",
  externalId: "o-abc123def4",
  parentExternalId: null,
  organizationId: "org-1",
  providerCount: 3,
  providerIds: ["provider-1", "provider-2", "provider-hidden"],
  subRows: [providerOne, providerTwo],
};

const organizationalUnitRow: ProvidersTableRow = {
  id: "ou-1",
  rowType: PROVIDERS_ROW_TYPE.ORGANIZATION,
  groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION_UNIT,
  name: "Production OU",
  externalId: "ou-abc123",
  parentExternalId: "o-abc123def4",
  organizationId: "org-1",
  providerCount: 2,
  providerIds: ["provider-2", "provider-hidden-ou"],
  subRows: [providerTwo],
};

describe("ProvidersAccountsTable", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    dataTableMockState.nextSelection = {};
    getScheduleMock.mockResolvedValue(scheduleResponse);
  });

  it("passes scan schedule capability to provider row action columns", () => {
    // Given/When
    render(
      <ProvidersAccountsTable
        isCloud
        metadata={metadata}
        rows={[]}
        scanScheduleCapability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // Then
    expect(screen.getByTestId("providers-data-table")).toBeInTheDocument();
    expect(getColumnProvidersMock).toHaveBeenCalledWith(
      expect.any(Object),
      [],
      [],
      [],
      expect.any(Function),
      expect.any(Function),
      expect.any(Function),
      SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY,
    );
  });

  describe("schedule provider selection", () => {
    it("uses the selected provider id for provider rows", () => {
      // Given
      const rows = [providerOne, providerTwo];

      // When
      const result = computeSelectedScheduleProviders(rows, { "0": true });

      // Then
      expect(result.providerIds).toEqual(["provider-1"]);
      expect(result.providers.map((provider) => provider.providerId)).toEqual([
        "provider-1",
      ]);
    });

    it("uses every organization provider id when the organization is selected", () => {
      // Given
      const rows = [organizationRow];

      // When
      const result = computeSelectedScheduleProviders(rows, { "0": true });

      // Then
      expect(result.providerIds).toEqual([
        "provider-1",
        "provider-2",
        "provider-hidden",
      ]);
      expect(result.providers.map((provider) => provider.providerId)).toEqual([
        "provider-1",
        "provider-2",
      ]);
    });

    it("uses every organizational unit provider id when the OU is selected", () => {
      // Given
      const rows = [
        {
          ...organizationRow,
          subRows: [organizationalUnitRow],
        },
      ];

      // When
      const result = computeSelectedScheduleProviders(rows, { "0.0": true });

      // Then
      expect(result.providerIds).toEqual(["provider-2", "provider-hidden-ou"]);
    });

    it("deduplicates provider ids when an organization and child provider are selected", () => {
      // Given
      const rows = [organizationRow];

      // When
      const result = computeSelectedScheduleProviders(rows, {
        "0": true,
        "0.0": true,
      });

      // Then
      expect(result.providerIds).toEqual([
        "provider-1",
        "provider-2",
        "provider-hidden",
      ]);
    });

    it("uses only selected child providers when an organization is partially selected", () => {
      // Given
      const rows = [organizationRow, providerThree];

      // When
      const result = computeSelectedScheduleProviders(rows, {
        "0.1": true,
        "1": true,
      });

      // Then
      expect(result.providerIds).toEqual(["provider-2", "provider-3"]);
    });
  });

  it("shows the bulk schedule action for selected providers", async () => {
    // Given
    const user = userEvent.setup();
    dataTableMockState.nextSelection = { "0": true };
    render(
      <ProvidersAccountsTable
        isCloud
        metadata={metadata}
        rows={[providerOne]}
        scanScheduleCapability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Apply selection" }));

    // Then
    expect(
      screen.getByRole("button", {
        name: "Edit Scan Schedule (1 provider)",
      }),
    ).toBeInTheDocument();
  });

  it("passes selected organization provider ids and visible providers to the modal", async () => {
    // Given
    const user = userEvent.setup();
    dataTableMockState.nextSelection = { "0": true };
    render(
      <ProvidersAccountsTable
        isCloud
        metadata={metadata}
        rows={[organizationRow]}
        scanScheduleCapability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Apply selection" }));

    // When
    await user.click(
      screen.getByRole("button", {
        name: "Edit Scan Schedule (3 providers)",
      }),
    );

    // Then
    expect(getScheduleMock).toHaveBeenCalledWith("provider-1");
    expect(screen.getByTestId("schedule-provider-ids")).toHaveTextContent(
      "provider-1,provider-2,provider-hidden",
    );
    expect(screen.getByTestId("schedule-visible-providers")).toHaveTextContent(
      "provider-1,provider-2",
    );
  });

  it("hides the bulk schedule action when capability is manual only", async () => {
    // Given
    const user = userEvent.setup();
    dataTableMockState.nextSelection = { "0": true };
    render(
      <ProvidersAccountsTable
        isCloud
        metadata={metadata}
        rows={[providerOne]}
        scanScheduleCapability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Apply selection" }));

    // Then
    expect(
      screen.queryByRole("button", { name: /edit scan schedule/i }),
    ).not.toBeInTheDocument();
  });

  it("hides the bulk schedule action when capability is blocked", async () => {
    // Given
    const user = userEvent.setup();
    dataTableMockState.nextSelection = { "0": true };
    render(
      <ProvidersAccountsTable
        isCloud
        metadata={metadata}
        rows={[providerOne]}
        scanScheduleCapability={SCAN_SCHEDULE_CAPABILITY.BLOCKED}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Apply selection" }));

    // Then
    expect(
      screen.queryByRole("button", { name: /edit scan schedule/i }),
    ).not.toBeInTheDocument();
  });

  it("clears the selection after a successful bulk schedule save", async () => {
    // Given
    const user = userEvent.setup();
    dataTableMockState.nextSelection = { "0": true };
    render(
      <ProvidersAccountsTable
        isCloud
        metadata={metadata}
        rows={[providerOne]}
        scanScheduleCapability={SCAN_SCHEDULE_CAPABILITY.ADVANCED}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Apply selection" }));
    await user.click(
      screen.getByRole("button", {
        name: "Edit Scan Schedule (1 provider)",
      }),
    );

    // When
    await user.click(screen.getByRole("button", { name: "Simulate save" }));

    // Then
    expect(
      screen.queryByRole("button", { name: /edit scan schedule/i }),
    ).not.toBeInTheDocument();
  });
});
