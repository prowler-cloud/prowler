"use client";

import { CustomLink } from "@/components/ui/custom";

interface LinkToFindingsProps {
  scanId?: string;
  isDisabled?: boolean;
}

export const LinkToFindingsFromScan = ({
  scanId,
  isDisabled,
}: LinkToFindingsProps) => {
  return (
    <CustomLink
      href={`/findings?filter[scan__in]=${scanId}&filter[status__in]=FAIL`}
      ariaLabel="Go to Findings page"
      color="muted"
      variant="ghost"
      size="sm"
      isDisabled={isDisabled}
    >
      See Findings
    </CustomLink>
  );
};
