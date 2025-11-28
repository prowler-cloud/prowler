"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { FindingProps } from "@/types/components";

import { FindingDetail } from "./table/finding-detail";

interface FindingDetailsSheetProps {
  finding: FindingProps;
}

export const FindingDetailsSheet = ({ finding }: FindingDetailsSheetProps) => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      const params = new URLSearchParams(searchParams.toString());
      params.delete("id");
      router.push(`${pathname}?${params.toString()}`, { scroll: false });
    }
  };

  return (
    <Sheet open={true} onOpenChange={handleOpenChange}>
      <SheetContent className="my-4 max-h-[calc(100vh-2rem)] max-w-[95vw] overflow-y-auto pt-10 md:my-8 md:max-h-[calc(100vh-4rem)] md:max-w-[55vw]">
        <SheetHeader>
          <SheetTitle className="sr-only">Finding Details</SheetTitle>
          <SheetDescription className="sr-only">
            View the finding details
          </SheetDescription>
        </SheetHeader>
        <FindingDetail findingDetails={finding} />
      </SheetContent>
    </Sheet>
  );
};
