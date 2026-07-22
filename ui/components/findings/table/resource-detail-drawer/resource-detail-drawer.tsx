"use client";

import { usePathname } from "next/navigation";

import type { ResourceDrawerFinding } from "@/actions/findings";
import { DetailSidePanel } from "@/components/side-panel/detail-side-panel";
import { buildFocusedFindingContext } from "@/lib/lighthouse/context/contributions";
import type { FindingResourceRow } from "@/types";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";

import { ResourceDetailDrawerContent } from "./resource-detail-drawer-content";
import type { CheckMeta } from "./use-resource-detail-drawer";

interface ResourceDetailDrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  isLoading: boolean;
  isNavigating: boolean;
  checkMeta: CheckMeta | null;
  currentIndex: number;
  totalResources: number;
  currentResource: FindingResourceRow | null;
  currentFinding: ResourceDrawerFinding | null;
  otherFindings: ResourceDrawerFinding[];
  showSyntheticResourceHint?: boolean;
  onNavigatePrev: () => void;
  onNavigateNext: () => void;
  onMuteComplete: () => void;
  onTriageUpdate?: (input: UpdateFindingTriageInput) => void;
}

export function ResourceDetailDrawer({
  open,
  onOpenChange,
  isLoading,
  isNavigating,
  checkMeta,
  currentIndex,
  totalResources,
  currentResource,
  currentFinding,
  otherFindings,
  showSyntheticResourceHint = false,
  onNavigatePrev,
  onNavigateNext,
  onMuteComplete,
  onTriageUpdate,
}: ResourceDetailDrawerProps) {
  const pathname = usePathname();
  const context = currentResource
    ? buildFocusedFindingContext({
        pathname,
        findingId: currentFinding?.id ?? currentResource.findingId,
        checkId: currentFinding?.checkId ?? currentResource.checkId,
        severity: currentFinding?.severity ?? currentResource.severity,
        status: currentFinding?.status ?? currentResource.status,
        providerUid: currentFinding?.providerUid ?? currentResource.providerUid,
        resourceUid: currentFinding?.resourceUid ?? currentResource.resourceUid,
        region: currentFinding?.resourceRegion ?? currentResource.region,
      })
    : undefined;

  return (
    <DetailSidePanel
      open={open}
      onOpenChange={onOpenChange}
      title="Resource Finding Details"
      description="View finding details for the selected resource"
      context={context}
    >
      <ResourceDetailDrawerContent
        isLoading={isLoading}
        isNavigating={isNavigating}
        checkMeta={checkMeta}
        currentIndex={currentIndex}
        totalResources={totalResources}
        currentResource={currentResource}
        currentFinding={currentFinding}
        otherFindings={otherFindings}
        showSyntheticResourceHint={showSyntheticResourceHint}
        onNavigatePrev={onNavigatePrev}
        onNavigateNext={onNavigateNext}
        onMuteComplete={onMuteComplete}
        onTriageUpdate={onTriageUpdate}
      />
    </DetailSidePanel>
  );
}
