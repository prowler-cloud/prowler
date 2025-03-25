"use client";

import { CustomButton } from "@/components/ui/custom";

interface LinkToFindingsProps {
  scanId?: string;
  isDisabled?: boolean;
}

export const LinkToFindingsFromScan = ({
  scanId,
  isDisabled,
}: LinkToFindingsProps) => {
  return (
    <CustomButton
      asLink={`/findings?filter[scan__in]=${scanId}&filter[status__in]=FAIL`}
      ariaLabel="Go to Findings page"
      variant="ghost"
      className="text-xs font-medium text-default-500 hover:text-primary disabled:opacity-30"
      size="sm"
      isDisabled={isDisabled}
    >
      See Findings
    </CustomButton>
  );
};
