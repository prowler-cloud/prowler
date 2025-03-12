"use client";

// import { usePathname, useRouter, useSearchParams } from "next/navigation";
// import { useEffect } from "react";

import { FindingProps } from "@/types/components";

import { FindingDetail } from "./finding-detail";

export const DataTableRowDetails = ({
  // entityId,
  findingDetails,
}: {
  entityId: string;
  findingDetails: FindingProps;
}) => {
  // const router = useRouter();
  // const pathname = usePathname();
  // const searchParams = useSearchParams();

  // useEffect(() => {
  //   if (entityId) {
  //     const params = new URLSearchParams(searchParams.toString());
  //     params.set("id", entityId);
  //     router.push(`${pathname}?${params.toString()}`, { scroll: false });
  //   }

  //   return () => {
  //     if (entityId) {
  //       const cleanupParams = new URLSearchParams(searchParams.toString());
  //       cleanupParams.delete("id");
  //       router.push(`${pathname}?${cleanupParams.toString()}`, {
  //         scroll: false,
  //       });
  //     }
  //   };
  // }, [entityId, pathname, router, searchParams]);

  return <FindingDetail findingDetails={findingDetails} />;
};
