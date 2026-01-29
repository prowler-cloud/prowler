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
      <SheetContent className="minimal-scrollbar 3xl:w-1/3 h-full w-full overflow-x-hidden overflow-y-auto p-6 pt-10 outline-none md:w-1/2 md:max-w-none">
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
