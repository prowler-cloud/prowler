"use client";

import { X } from "lucide-react";

import {
  Drawer,
  DrawerClose,
  DrawerContent,
  DrawerDescription,
  DrawerHeader,
  DrawerTitle,
} from "@/components/shadcn";
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
    <Drawer direction="right" open={open} onOpenChange={onOpenChange}>
      <DrawerContent className="3xl:w-1/3 h-full w-full overflow-hidden p-6 outline-none md:w-1/2 md:max-w-none md:min-w-[720px]">
        <DrawerHeader className="sr-only">
          <DrawerTitle>Resource Details</DrawerTitle>
          <DrawerDescription>View the resource details</DrawerDescription>
        </DrawerHeader>
        <DrawerClose className="ring-offset-background focus:ring-ring absolute top-4 right-4 rounded-sm opacity-70 transition-opacity hover:opacity-100 focus:ring-2 focus:ring-offset-2 focus:outline-none">
          <X className="size-4" />
          <span className="sr-only">Close</span>
        </DrawerClose>
        {open && <ResourceDetailContent resourceDetails={resource} />}
      </DrawerContent>
    </Drawer>
  );
};
