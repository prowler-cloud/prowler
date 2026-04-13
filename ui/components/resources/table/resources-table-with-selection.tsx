"use client";

import { useEffect, useRef, useState } from "react";

import { getResourceById } from "@/actions/resources";
import { ResourceDetailsSheet } from "@/components/resources/resource-details-sheet";
import { DataTable } from "@/components/ui/table";
import { createDict } from "@/lib";
import { MetaDataProps, ResourceProps } from "@/types";

import { getColumnResources } from "./column-resources";

interface ResourcesTableWithSelectionProps {
  data: ResourceProps[];
  metadata?: MetaDataProps;
  initialResourceId?: string;
}

export function ResourcesTableWithSelection({
  data,
  metadata,
  initialResourceId,
}: ResourcesTableWithSelectionProps) {
  const safeData = data ?? [];

  const [selectedResource, setSelectedResource] =
    useState<ResourceProps | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const initializedRef = useRef(false);

  useEffect(() => {
    if (initializedRef.current || !initialResourceId) return;
    initializedRef.current = true;

    const found = data?.find((r) => r.id === initialResourceId);
    if (found) {
      setSelectedResource(found);
      setDrawerOpen(true);
      return;
    }

    getResourceById(initialResourceId, { include: ["provider"] }).then(
      (response) => {
        if (!response?.data) return;
        const resource = response.data;
        const providerDict = createDict("providers", response);
        const provider = {
          data: providerDict[resource.relationships?.provider?.data?.id],
        };
        setSelectedResource({
          ...resource,
          relationships: { ...resource.relationships, provider },
        } as ResourceProps);
        setDrawerOpen(true);
      },
    );
  }, [initialResourceId, data]);

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
