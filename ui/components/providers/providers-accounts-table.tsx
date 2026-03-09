"use client";

import { DataTable } from "@/components/ui/table";
import { MetaDataProps } from "@/types";
import { ProvidersTableRow } from "@/types/providers-table";

import { ColumnProviders } from "./table";

interface ProvidersAccountsTableProps {
  isCloud: boolean;
  metadata?: MetaDataProps;
  rows: ProvidersTableRow[];
}

export function ProvidersAccountsTable({
  isCloud,
  metadata,
  rows,
}: ProvidersAccountsTableProps) {
  return (
    <DataTable
      columns={ColumnProviders}
      data={rows}
      metadata={metadata}
      getSubRows={(row) => row.subRows}
      defaultExpanded={isCloud}
      showSearch
    />
  );
}
