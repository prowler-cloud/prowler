"use client";

import { DataTable } from "@/components/ui/table";
import { MetaDataProps, ResourceProps } from "@/types";

import { ColumnResources } from "./column-resources";

interface ResourcesTableWithSelectionProps {
  data: ResourceProps[];
  metadata?: MetaDataProps;
}

export function ResourcesTableWithSelection({
  data,
  metadata,
}: ResourcesTableWithSelectionProps) {
  // Ensure data is always an array for safe operations
  const safeData = data ?? [];

  return (
    <DataTable
      columns={ColumnResources}
      data={safeData}
      metadata={metadata}
      showSearch
    />
  );
}
