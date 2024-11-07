"use client";

import { useEffect, useState } from "react";

import { FindingDetail } from "@/components/findings/table";
import { FindingProps } from "@/types";

export const DataTableRowDetails = ({ finding }: { finding: FindingProps }) => {
  console.log(finding);
  return <FindingDetail findingDetails={finding} />;
};
