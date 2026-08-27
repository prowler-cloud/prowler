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
  // Forwarded to DetailSidePanel: false opens the Details tab without
  // selecting it (skill launches keep the AI chat tab in front).
  selectTabOnOpen?: boolean;
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
  selectTabOnOpen,
  onNavigatePrev,
  onNavigateNext,
  onMuteComplete,
  onTriageUpdate,
}: ResourceDetailDrawerProps) {
  const pathname = usePathname();
  const focusedFinding = isNavigating ? null : currentFinding;
  const context = currentResource
    ? buildFocusedFindingContext({
        pathname,
        findingId: focusedFinding?.id ?? currentResource.findingId,
        checkId: focusedFinding?.checkId ?? currentResource.checkId,
        severity: focusedFinding?.severity ?? currentResource.severity,
        status: focusedFinding?.status ?? currentResource.status,
        providerUid: focusedFinding?.providerUid ?? currentResource.providerUid,
        resourceUid: focusedFinding?.resourceUid ?? currentResource.resourceUid,
        region: focusedFinding?.resourceRegion ?? currentResource.region,
      })
    : undefined;

  return (
    <DetailSidePanel
      open={open}
      onOpenChange={onOpenChange}
      title="Resource Finding Details"
      description="View finding details for the selected resource"
      context={context}
      selectTabOnOpen={selectTabOnOpen}
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
