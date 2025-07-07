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
      path={`/findings?filter[scan__in]=${scanId}&filter[status__in]=FAIL`}
      ariaLabel="Go to Findings page"
      color="muted"
      className="w-[7rem] rounded-md border border-prowler-theme-green px-4 py-2 text-xs !font-bold text-default-500 hover:bg-prowler-theme-green hover:!text-black disabled:opacity-30"
      isDisabled={isDisabled}
    >
      See Findings
    </CustomLink>
  );
};
