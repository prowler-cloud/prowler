"use client";

import { FindingProps } from "@/types/components";

import { FindingDetail } from "./finding-detail";

export const DataTableRowDetails = ({
  findingDetails,
}: {
  entityId: string;
  findingDetails: FindingProps;
}) => {
  return <FindingDetail findingDetails={findingDetails} />;
};
