"use client";

import type { ReactNode } from "react";

import { findingToFindingResourceRow } from "@/lib/finding-detail";
import type { FindingProps } from "@/types/components";

import {
  ResourceDetailDrawer,
  useResourceDetailDrawer,
} from "./resource-detail-drawer";
import { ResourceDetailDrawerContent } from "./resource-detail-drawer/resource-detail-drawer-content";

interface FindingDetailDrawerProps {
  finding: FindingProps;
  trigger?: ReactNode;
  defaultOpen?: boolean;
  inline?: boolean;
  onOpenChange?: (open: boolean) => void;
  onMuteComplete?: () => void;
}

export function FindingDetailDrawer({
  finding,
  trigger,
  defaultOpen = false,
  inline = false,
  onOpenChange,
  onMuteComplete,
}: FindingDetailDrawerProps) {
  const drawer = useResourceDetailDrawer({
    resources: [findingToFindingResourceRow(finding)],
    totalResourceCount: 1,
    initialIndex: defaultOpen || inline ? 0 : null,
  });

  const handleOpen = () => {
    drawer.openDrawer(0);
    onOpenChange?.(true);
  };

  const handleOpenChange = (open: boolean) => {
    if (open) {
      drawer.openDrawer(0);
    } else {
      drawer.closeDrawer();
    }

    onOpenChange?.(open);
  };

  const handleMuteComplete = () => {
    drawer.refetchCurrent();
    onMuteComplete?.();
  };

  if (inline) {
    return (
      <ResourceDetailDrawerContent
        isLoading={drawer.isLoading}
        isNavigating={drawer.isNavigating}
        checkMeta={drawer.checkMeta}
        currentIndex={drawer.currentIndex}
        totalResources={drawer.totalResources}
        currentResource={drawer.currentResource}
        currentFinding={drawer.currentFinding}
        otherFindings={drawer.otherFindings}
        onNavigatePrev={drawer.navigatePrev}
        onNavigateNext={drawer.navigateNext}
        onMuteComplete={handleMuteComplete}
      />
    );
  }

  return (
    <>
      {trigger ? (
        <button type="button" className="contents" onClick={handleOpen}>
          {trigger}
        </button>
      ) : null}
      <ResourceDetailDrawer
        open={drawer.isOpen}
        onOpenChange={handleOpenChange}
        isLoading={drawer.isLoading}
        isNavigating={drawer.isNavigating}
        checkMeta={drawer.checkMeta}
        currentIndex={drawer.currentIndex}
        totalResources={drawer.totalResources}
        currentResource={drawer.currentResource}
        currentFinding={drawer.currentFinding}
        otherFindings={drawer.otherFindings}
        onNavigatePrev={drawer.navigatePrev}
        onNavigateNext={drawer.navigateNext}
        onMuteComplete={handleMuteComplete}
      />
    </>
  );
}
