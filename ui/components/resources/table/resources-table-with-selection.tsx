"use client";

import { useState } from "react";

import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { ResourceDetailsSheet } from "@/components/resources/resource-details-sheet";
import { DataTable } from "@/components/shadcn/table";
import { buildResourceSummaryContext } from "@/lib/lighthouse/context/contributions";
import { MetaDataProps, ResourceProps } from "@/types";

import { getColumnResources } from "./column-resources";

interface ResourcesTableWithSelectionProps {
  data: ResourceProps[];
  metadata?: MetaDataProps;
  initialResource?: ResourceProps | null;
  /** Sample rows must not reach Lighthouse, not even as a count. */
  contributeLighthouseContext?: boolean;
}

export function ResourcesTableWithSelection({
  data,
  metadata,
  initialResource = null,
  contributeLighthouseContext = true,
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
      {contributeLighthouseContext &&
        metadata?.pagination.count !== undefined && (
          <LighthouseContextContributor
            key={`resources-summary-${metadata.pagination.count}`}
            contributorId="resources-summary"
            item={buildResourceSummaryContext(metadata.pagination.count)}
          />
        )}
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
