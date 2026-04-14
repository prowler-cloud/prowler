"use client";

import { RowSelectionState } from "@tanstack/react-table";
import { useEffect, useState } from "react";

import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import { DataTable } from "@/components/ui/table";
import { MetaDataProps } from "@/types";
import {
  isProvidersOrganizationRow,
  ProvidersTableRow,
} from "@/types/providers-table";

import { getColumnProviders } from "./table";

interface ProvidersAccountsTableProps {
  isCloud: boolean;
  metadata?: MetaDataProps;
  rows: ProvidersTableRow[];
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

export function ProvidersAccountsTable({
  isCloud,
  metadata,
  rows,
  onOpenProviderWizard,
  onOpenOrganizationWizard,
}: ProvidersAccountsTableProps) {
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});

  // Reset selection when page changes
  const currentPage = metadata?.pagination?.page;
  useEffect(() => {
    setRowSelection({});
  }, [currentPage]);

  const testableProviderIds = computeTestableProviderIds(rows, rowSelection);

  const clearSelection = () => setRowSelection({});

  const columns = getColumnProviders(
    rowSelection,
    testableProviderIds,
    clearSelection,
    onOpenProviderWizard,
    onOpenOrganizationWizard,
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
