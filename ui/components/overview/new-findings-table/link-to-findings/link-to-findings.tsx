"use client";

import { AddIcon } from "@/components/icons";
import { CustomButton } from "@/components/ui/custom";

export const LinkToFindings = () => {
  return (
    <div className="mt-4 flex w-full items-center justify-end">
      <CustomButton
        asLink="/findings?filter[severity]=critical&filter[delta__in]=new&filter[status__in]=FAIL"
        ariaLabel="Go to Findings page"
        variant="solid"
        color="action"
        size="sm"
        endContent={<AddIcon size={20} />}
      >
        Check out on findings
      </CustomButton>
    </div>
  );
};
