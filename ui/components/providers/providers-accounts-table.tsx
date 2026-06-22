"use client";

import { RowSelectionState } from "@tanstack/react-table";
import { CalendarClock } from "lucide-react";
import { useState } from "react";

import { getSchedule } from "@/actions/schedules";
import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import {
  EDIT_SCAN_SCHEDULE_STATE,
  EditScanScheduleModal,
  type EditScanScheduleState,
  type ScanScheduleProvider,
} from "@/components/scans/schedule/edit-scan-schedule-modal";
import { Button } from "@/components/shadcn";
import { DataTable } from "@/components/ui/table";
import { getScanScheduleCapability } from "@/lib/schedules";
import { MetaDataProps } from "@/types";
import {
  isProvidersOrganizationRow,
  isProvidersProviderRow,
  ProvidersTableRow,
} from "@/types/providers-table";
import {
  SCAN_SCHEDULE_CAPABILITY,
  type ScanScheduleCapability,
  type ScheduleApiResponse,
} from "@/types/schedules";

import { getColumnProviders } from "./table";

interface ProvidersAccountsTableProps {
  isCloud: boolean;
  metadata?: MetaDataProps;
  rows: ProvidersTableRow[];
  scanScheduleCapability?: ScanScheduleCapability;
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

function getProviderCountLabel(count: number) {
  return `${count} provider${count === 1 ? "" : "s"}`;
}

function ProvidersAccountsTableContent({
  isCloud,
  metadata,
  rows,
  scanScheduleCapability,
  onOpenProviderWizard,
  onOpenOrganizationWizard,
}: ProvidersAccountsTableProps) {
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [isScheduleOpen, setIsScheduleOpen] = useState(false);
  const [scheduleState, setScheduleState] = useState<EditScanScheduleState>({
    kind: EDIT_SCAN_SCHEDULE_STATE.LOADING,
  });

  const testableProviderIds = computeTestableProviderIds(rows, rowSelection);
  const selectedScheduleProviders = computeSelectedScheduleProviders(
    rows,
    rowSelection,
  );
  const selectedScheduleProviderIds = selectedScheduleProviders.providerIds;
  const canEditBulkSchedule =
    (scanScheduleCapability ?? getScanScheduleCapability(isCloud)) ===
    SCAN_SCHEDULE_CAPABILITY.ADVANCED;

  const clearSelection = () => setRowSelection({});

  const openBulkScheduleEditor = async () => {
    const targetProviderId = selectedScheduleProviderIds[0];
    if (!targetProviderId) return;

    setScheduleState({ kind: EDIT_SCAN_SCHEDULE_STATE.LOADING });
    setIsScheduleOpen(true);

    const response = (await getSchedule(targetProviderId)) as
      | ScheduleApiResponse
      | { error?: string };

    if (!response || ("error" in response && response.error)) {
      setScheduleState({
        kind: EDIT_SCAN_SCHEDULE_STATE.ERROR,
        message:
          response && "error" in response && response.error
            ? response.error
            : "Failed to load scan schedule.",
      });
      return;
    }

    setScheduleState({
      kind: EDIT_SCAN_SCHEDULE_STATE.LOADED,
      schedule: "data" in response ? response.data : null,
    });
  };

  const columns = getColumnProviders(
    rowSelection,
    testableProviderIds,
    selectedScheduleProviderIds,
    selectedScheduleProviders.providers,
    clearSelection,
    onOpenProviderWizard,
    onOpenOrganizationWizard,
    scanScheduleCapability,
  );

  const selectedScheduleProviderCount = selectedScheduleProviderIds.length;
  const toolbarRightContent =
    canEditBulkSchedule && selectedScheduleProviderCount > 0 ? (
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => void openBulkScheduleEditor()}
      >
        <CalendarClock className="size-4" />
        {`Edit Scan Schedule (${getProviderCountLabel(selectedScheduleProviderCount)})`}
      </Button>
    ) : undefined;

  return (
    <>
      <EditScanScheduleModal
        open={isScheduleOpen}
        onOpenChange={setIsScheduleOpen}
        providers={selectedScheduleProviders.providers}
        providerIds={selectedScheduleProviderIds}
        targetName="Selected providers"
        state={scheduleState}
        onSaved={clearSelection}
      />
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
        toolbarRightContent={toolbarRightContent}
      />
    </>
  );
}

export function ProvidersAccountsTable(props: ProvidersAccountsTableProps) {
  const currentPage = props.metadata?.pagination?.page ?? "none";

  return <ProvidersAccountsTableContent key={currentPage} {...props} />;
}
