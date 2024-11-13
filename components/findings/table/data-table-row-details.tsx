"use client";

import { FindingDetail } from "@/components/findings/table";
import { FindingProps } from "@/types";

export const DataTableRowDetails = ({ finding }: { finding: FindingProps }) => {
  return <FindingDetail findingDetails={finding} />;
};
