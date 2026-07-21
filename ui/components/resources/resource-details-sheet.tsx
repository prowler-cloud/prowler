"use client";

import { DetailSidePanel } from "@/components/side-panel/detail-side-panel";
import { ResourceProps } from "@/types";

import { ResourceDetailContent } from "./table/resource-detail-content";

interface ResourceDetailsSheetProps {
  resource: ResourceProps;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export const ResourceDetailsSheet = ({
  resource,
  open,
  onOpenChange,
}: ResourceDetailsSheetProps) => {
  return (
    <DetailSidePanel
      open={open}
      onOpenChange={onOpenChange}
      title="Resource Details"
      description="View the resource details"
    >
      <ResourceDetailContent key={resource.id} resourceDetails={resource} />
    </DetailSidePanel>
  );
};
