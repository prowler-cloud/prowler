"use client";

import { CustomButton } from "@/components/ui/custom";

interface LinkToFindingsProps {
  scanId?: string;
}

export const LinkToFindingsFromScan = ({ scanId }: LinkToFindingsProps) => {
  return (
    <CustomButton
      asLink={`/findings?filter[scan__in]=${scanId}`}
      ariaLabel="Go to Findings page"
      variant="solid"
      color="action"
      size="sm"
    >
      See Findings
    </CustomButton>
  );
};
