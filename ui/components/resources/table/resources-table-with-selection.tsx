"use client";

import { useState } from "react";

import { ResourceDetailsSheet } from "@/components/resources/resource-details-sheet";
import { DataTable } from "@/components/ui/table";
import { MetaDataProps, ResourceProps } from "@/types";

import { getColumnResources } from "./column-resources";

interface ResourcesTableWithSelectionProps {
  data: ResourceProps[];
  metadata?: MetaDataProps;
  initialResource?: ResourceProps | null;
}

export function ResourcesTableWithSelection({
  data,
  metadata,
  initialResource = null,
}: ResourcesTableWithSelectionProps) {
  const safeData = data ?? [];

  const [selectedResource, setSelectedResource] =
    useState<ResourceProps | null>(initialResource);
  const [drawerOpen, setDrawerOpen] = useState(Boolean(initialResource));

  const openDrawer = (resource: ResourceProps) => {
    setSelectedResource(resource);
    setDrawerOpen(true);
  };

  const columns = getColumnResources({ onViewDetails: openDrawer });

  return (
    <>
      <DataTable
        columns={columns}
        data={safeData}
        metadata={metadata}
        showSearch
        onRowClick={(row) => openDrawer(row.original)}
      />
      {selectedResource && (
        <ResourceDetailsSheet
          resource={selectedResource}
          open={drawerOpen}
          onOpenChange={(open) => {
            setDrawerOpen(open);
            if (!open) setSelectedResource(null);
          }}
        />
      )}
    </>
  );
}
