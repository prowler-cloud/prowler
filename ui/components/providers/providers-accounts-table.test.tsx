import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { MetaDataProps } from "@/types";
import {
  PROVIDERS_GROUP_KIND,
  PROVIDERS_ROW_TYPE,
  type ProvidersTableRow,
} from "@/types/providers-table";
import {
  SCAN_CONFIGURATION_LIST_STATUS,
  type ScanConfigurationData,
} from "@/types/scan-configurations";
import { SCAN_SCHEDULE_CAPABILITY } from "@/types/schedules";

const { dataTableMockState, getColumnProvidersMock } = vi.hoisted(() => ({
  dataTableMockState: {
    nextSelection: {} as Record<string, boolean>,
  },
  getColumnProvidersMock: vi.fn((..._args: unknown[]) => []),
}));

vi.mock("@/components/shadcn/table", () => ({
  DataTable: ({
    onRowSelectionChange,
  }: {
    onRowSelectionChange?: (selection: Record<string, boolean>) => void;
  }) => (
    <div data-testid="providers-data-table">
      <button
        type="button"
        onClick={() => onRowSelectionChange?.(dataTableMockState.nextSelection)}
      >
        Apply selection
      </button>
    </div>
  ),
}));

vi.mock("./table", () => ({
  getColumnProviders: (...args: unknown[]) => getColumnProvidersMock(...args),
}));

import {
  computeSelectedScheduleProviders,
  createScanConfigIdByProviderId,
  ProvidersAccountsTable,
} from "./providers-accounts-table";

const metadata: MetaDataProps = {
  pagination: { page: 1, pages: 1, count: 0, itemsPerPage: [10] },
  version: "latest",
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
      [],
      SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE,
      expect.any(Map),
    );
  });

  it("passes populated scan configs to provider row action columns", () => {
    // Given/When
    render(
      <ProvidersAccountsTable
        isCloud
        metadata={metadata}
        rows={[]}
        scanConfigs={[scanConfig]}
        scanScheduleCapability={SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY}
        onOpenProviderWizard={vi.fn()}
        onOpenOrganizationWizard={vi.fn()}
      />,
    );

    // Then
    const call = getColumnProvidersMock.mock.calls.at(-1);
    expect(call?.[8]).toEqual([scanConfig]);
    expect(call?.[9]).toBe(SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE);
    expect(call?.[10]).toBeInstanceOf(Map);
    expect((call?.[10] as Map<string, string>).get("provider-1")).toBe(
      "config-1",
    );
  });

  it("precomputes scan config ids by provider id once for row actions", () => {
    // Given/When
    const lookup = createScanConfigIdByProviderId([scanConfig]);

    // Then
    expect(lookup.get("provider-1")).toBe("config-1");
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

  it("passes selected provider ids to provider row action columns", async () => {
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
    expect(getColumnProvidersMock).toHaveBeenLastCalledWith(
      expect.any(Object),
      ["provider-1"],
      ["provider-1"],
      [
        expect.objectContaining({
          providerId: "provider-1",
          providerType: "aws",
          providerUid: "111111111111",
          providerAlias: "Prod",
        }),
      ],
      expect.any(Function),
      expect.any(Function),
      expect.any(Function),
      SCAN_SCHEDULE_CAPABILITY.ADVANCED,
      [],
      SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE,
      expect.any(Map),
    );
  });

  it("passes selected organization provider ids and visible providers to provider row action columns", async () => {
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

    // Then
    expect(getColumnProvidersMock).toHaveBeenLastCalledWith(
      expect.any(Object),
      [],
      ["provider-1", "provider-2", "provider-hidden"],
      [
        expect.objectContaining({ providerId: "provider-1" }),
        expect.objectContaining({ providerId: "provider-2" }),
      ],
      expect.any(Function),
      expect.any(Function),
      expect.any(Function),
      SCAN_SCHEDULE_CAPABILITY.ADVANCED,
      [],
      SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE,
      expect.any(Map),
    );
  });
});
