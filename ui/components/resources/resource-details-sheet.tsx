"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { ResourceProps } from "@/types";

import { ResourceDetail } from "./table/resource-detail";

interface ResourceDetailsSheetProps {
  resource: ResourceProps;
}

export const ResourceDetailsSheet = ({
  resource,
}: ResourceDetailsSheetProps) => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      const params = new URLSearchParams(searchParams.toString());
      params.delete("resourceId");
      router.push(`${pathname}?${params.toString()}`, { scroll: false });
    }
  };

  return (
    <Sheet open={true} onOpenChange={handleOpenChange}>
      <SheetContent className="my-4 max-h-[calc(100vh-2rem)] max-w-[95vw] overflow-y-auto pt-10 md:my-8 md:max-h-[calc(100vh-4rem)] md:max-w-[55vw]">
        <SheetHeader>
          <SheetTitle className="sr-only">Resource Details</SheetTitle>
          <SheetDescription className="sr-only">
            View the resource details
          </SheetDescription>
        </SheetHeader>
        <ResourceDetail resourceDetails={resource} />
      </SheetContent>
    </Sheet>
  );
};
