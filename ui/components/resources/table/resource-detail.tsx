"use client";

import { X } from "lucide-react";
import type { ReactNode } from "react";
import { useState } from "react";

import {
  Drawer,
  DrawerClose,
  DrawerContent,
  DrawerDescription,
  DrawerHeader,
  DrawerTitle,
  DrawerTrigger,
} from "@/components/shadcn";
import { ResourceProps } from "@/types";

import { ResourceDetailContent } from "./resource-detail-content";

interface ResourceDetailProps {
  resourceDetails: ResourceProps;
  trigger?: ReactNode;
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
}

/**
 * Lightweight wrapper component for resource details.
 *
 * When used with a trigger (table rows), this component only renders the Drawer shell
 * and trigger. The heavy ResourceDetailContent is only mounted when the drawer is open,
 * preventing unnecessary state initialization and data fetching for closed drawers.
 *
 * When used without a trigger (inline mode from ResourceDetailsSheet), it renders
 * the content directly since it's already visible.
 */
export const ResourceDetail = ({
  resourceDetails,
  trigger,
  open: controlledOpen,
  defaultOpen = false,
  onOpenChange,
}: ResourceDetailProps) => {
  // Track internal open state for uncontrolled drawer (when using trigger)
  const [internalOpen, setInternalOpen] = useState(defaultOpen);

  // Determine actual open state
  const isOpen = controlledOpen ?? internalOpen;

  // Handle open state changes
  const handleOpenChange = (newOpen: boolean) => {
    setInternalOpen(newOpen);
    onOpenChange?.(newOpen);
  };

  // If no trigger, render content directly (inline mode for ResourceDetailsSheet)
  if (!trigger) {
    return <ResourceDetailContent resourceDetails={resourceDetails} />;
  }

  // With trigger, wrap in Drawer - content only mounts when open (lazy loading)
  return (
    <Drawer
      direction="right"
      open={isOpen}
      defaultOpen={defaultOpen}
      onOpenChange={handleOpenChange}
    >
      <DrawerTrigger asChild>{trigger}</DrawerTrigger>
      <DrawerContent className="minimal-scrollbar 3xl:w-1/3 h-full w-full overflow-x-hidden overflow-y-auto p-6 outline-none md:w-1/2 md:max-w-none">
        <DrawerHeader className="sr-only">
          <DrawerTitle>Resource Details</DrawerTitle>
          <DrawerDescription>View the resource details</DrawerDescription>
        </DrawerHeader>
        <DrawerClose className="ring-offset-background focus:ring-ring absolute top-4 right-4 rounded-sm opacity-70 transition-opacity hover:opacity-100 focus:ring-2 focus:ring-offset-2 focus:outline-none">
          <X className="size-4" />
          <span className="sr-only">Close</span>
        </DrawerClose>
        {/* Content only renders when drawer is open - this is the key optimization */}
        {isOpen && <ResourceDetailContent resourceDetails={resourceDetails} />}
      </DrawerContent>
    </Drawer>
  );
};
