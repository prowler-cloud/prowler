"use client";

import { CheckFindings } from "./check-findings";

interface OverviewTabProps {
  isActive: boolean;
  failFindingsData: {
    total: number;
    new: number;
    muted: number;
  };
  passFindingsData: {
    total: number;
    new: number;
    muted: number;
  };
}

export function OverviewTab({
  failFindingsData,
  passFindingsData,
}: OverviewTabProps) {
  return (
    <CheckFindings
      failFindingsData={failFindingsData}
      passFindingsData={passFindingsData}
    />
  );
}
