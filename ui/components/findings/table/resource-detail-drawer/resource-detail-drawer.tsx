"use client";

import { X } from "lucide-react";

import type { ResourceDrawerFinding } from "@/actions/findings";
import {
  Drawer,
  DrawerClose,
  DrawerContent,
  DrawerDescription,
  DrawerHeader,
  DrawerTitle,
} from "@/components/shadcn";
import type { FindingResourceRow } from "@/types";

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
}: ResourceDetailDrawerProps) {
  return (
    <Drawer direction="right" open={open} onOpenChange={onOpenChange}>
      <DrawerContent className="3xl:w-1/3 h-full w-full overflow-hidden p-6 outline-none md:w-1/2 md:max-w-none md:min-w-[720px]">
        <DrawerHeader className="sr-only">
          <DrawerTitle>Resource Finding Details</DrawerTitle>
          <DrawerDescription>
            View finding details for the selected resource
          </DrawerDescription>
        </DrawerHeader>
        <DrawerClose className="ring-offset-background focus:ring-ring absolute top-4 right-4 rounded-sm opacity-70 transition-opacity hover:opacity-100 focus:ring-2 focus:ring-offset-2 focus:outline-none">
          <X className="size-4" />
          <span className="sr-only">Close</span>
        </DrawerClose>
        {open && (
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
          />
        )}
      </DrawerContent>
    </Drawer>
  );
}
