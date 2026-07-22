"use client";

import { usePathname } from "next/navigation";

import { DetailSidePanel } from "@/components/side-panel/detail-side-panel";
import { buildFocusedResourceContext } from "@/lib/lighthouse/context/contributions";
import type { ResourceProps } from "@/types";

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
  const pathname = usePathname();
  const context = buildFocusedResourceContext({
    pathname,
    id: resource.id,
    attributes: resource.attributes,
    providerUid: resource.relationships.provider.data.attributes.uid,
  });

  return (
    <DetailSidePanel
      open={open}
      onOpenChange={onOpenChange}
      title="Resource Details"
      description="View the resource details"
      context={context}
    >
      <ResourceDetailContent key={resource.id} resourceDetails={resource} />
    </DetailSidePanel>
  );
};
