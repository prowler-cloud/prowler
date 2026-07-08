"use client";

import { RowSelectionState } from "@tanstack/react-table";
import { useState } from "react";

import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import { DataTable } from "@/components/shadcn/table";
import { MetaDataProps } from "@/types";
import {
  isProvidersOrganizationRow,
  isProvidersProviderRow,
  ProvidersTableRow,
} from "@/types/providers-table";
import {
  SCAN_CONFIGURATION_LIST_STATUS,
  ScanConfigurationData,
  type ScanConfigurationListStatus,
} from "@/types/scan-configurations";
import type {
  ScanScheduleCapability,
  ScanScheduleProvider,
} from "@/types/schedules";

import { getColumnProviders } from "./table";

interface ProvidersAccountsTableProps {
  isCloud: boolean;
  metadata?: MetaDataProps;
  rows: ProvidersTableRow[];
  scanScheduleCapability?: ScanScheduleCapability;
  /** All scan configurations in the tenant, for the provider row's associate/
   * disassociate action (Cloud-only). */
  scanConfigs?: ScanConfigurationData[];
  scanConfigStatus?: ScanConfigurationListStatus;
  onOpenProviderWizard: (initialData?: ProviderWizardInitialData) => void;
  onOpenOrganizationWizard: (initialData: OrgWizardInitialData) => void;
}

function computeTestableProviderIds(
  rows: ProvidersTableRow[],
  rowSelection: RowSelectionState,
): string[] {
  const ids: string[] = [];

  function walk(items: ProvidersTableRow[], prefix: string) {
    items.forEach((item, idx) => {
      const key = prefix ? `${prefix}.${idx}` : `${idx}`;
      if (
        rowSelection[key] &&
        !isProvidersOrganizationRow(item) &&
        item.relationships.secret.data
      ) {
        ids.push(item.id);
      }
      if (item.subRows) {
        walk(item.subRows, key);
      }
    });
  }

  walk(rows, "");
  return ids;
}

function toScanScheduleProvider(
  row: ProvidersTableRow,
): ScanScheduleProvider | null {
  if (!isProvidersProviderRow(row)) return null;

  return {
    providerId: row.id,
    providerType: row.attributes.provider,
    providerUid: row.attributes.uid,
    providerAlias: row.attributes.alias,
  };
}

function appendUnique(target: string[], seen: Set<string>, ids: string[]) {
  for (const id of ids) {
    if (seen.has(id)) continue;
    seen.add(id);
    target.push(id);
  }
}

function appendUniqueProvider(
  target: ScanScheduleProvider[],
  seen: Set<string>,
  provider: ScanScheduleProvider | null,
) {
  if (!provider || seen.has(provider.providerId)) return;
  seen.add(provider.providerId);
  target.push(provider);
}

function collectVisibleScheduleProviders(rows: ProvidersTableRow[]) {
  const providers: ScanScheduleProvider[] = [];
  const seen = new Set<string>();

  function walk(items: ProvidersTableRow[]) {
    for (const item of items) {
      appendUniqueProvider(providers, seen, toScanScheduleProvider(item));
      if (isProvidersOrganizationRow(item)) {
        walk(item.subRows);
      }
    }
  }

  walk(rows);
  return providers;
}

export interface SelectedScheduleProvidersResult {
  providerIds: string[];
  providers: ScanScheduleProvider[];
}

export function computeSelectedScheduleProviders(
  rows: ProvidersTableRow[],
  rowSelection: RowSelectionState,
): SelectedScheduleProvidersResult {
  const providerIds: string[] = [];
  const providers: ScanScheduleProvider[] = [];
  const seenProviderIds = new Set<string>();
  const seenVisibleProviders = new Set<string>();

  function walk(items: ProvidersTableRow[], prefix: string) {
    items.forEach((item, idx) => {
      const key = prefix ? `${prefix}.${idx}` : `${idx}`;
      const isSelected = rowSelection[key] === true;

      if (isProvidersOrganizationRow(item)) {
        if (isSelected) {
          appendUnique(providerIds, seenProviderIds, item.providerIds);
          for (const provider of collectVisibleScheduleProviders(
            item.subRows,
          )) {
            appendUniqueProvider(providers, seenVisibleProviders, provider);
          }
          return;
        }

        walk(item.subRows, key);
        return;
      }

      if (isSelected) {
        appendUnique(providerIds, seenProviderIds, [item.id]);
        appendUniqueProvider(
          providers,
          seenVisibleProviders,
          toScanScheduleProvider(item),
        );
      }
    });
  }

  walk(rows, "");

  return { providerIds, providers };
}

export function createScanConfigIdByProviderId(
  scanConfigs: ScanConfigurationData[],
): Map<string, string> {
  const lookup = new Map<string, string>();

  for (const config of scanConfigs) {
    for (const providerId of config.attributes.providers) {
      lookup.set(providerId, config.id);
    }
  }

  return lookup;
}

function ProvidersAccountsTableContent({
  isCloud,
  metadata,
  rows,
  scanScheduleCapability,
  scanConfigs,
  scanConfigStatus = SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE,
  onOpenProviderWizard,
  onOpenOrganizationWizard,
}: ProvidersAccountsTableProps) {
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});

  const testableProviderIds = computeTestableProviderIds(rows, rowSelection);
  const selectedScheduleProviders = computeSelectedScheduleProviders(
    rows,
    rowSelection,
  );
  const selectedScheduleProviderIds = selectedScheduleProviders.providerIds;
  const scanConfigIdByProviderId = createScanConfigIdByProviderId(
    scanConfigs ?? [],
  );

  const clearSelection = () => setRowSelection({});

  const columns = getColumnProviders(
    rowSelection,
    testableProviderIds,
    selectedScheduleProviderIds,
    selectedScheduleProviders.providers,
    clearSelection,
    onOpenProviderWizard,
    onOpenOrganizationWizard,
    scanScheduleCapability,
    scanConfigs ?? [],
    scanConfigStatus,
    scanConfigIdByProviderId,
  );

  return (
    <DataTable
      columns={columns}
      data={rows}
      metadata={metadata}
      getSubRows={(row) => row.subRows}
      defaultExpanded={isCloud}
      showSearch
      enableRowSelection
      rowSelection={rowSelection}
      onRowSelectionChange={setRowSelection}
      enableSubRowSelection
    />
  );
}

export function ProvidersAccountsTable(props: ProvidersAccountsTableProps) {
  const currentPage = props.metadata?.pagination?.page ?? "none";

  return <ProvidersAccountsTableContent key={currentPage} {...props} />;
}
