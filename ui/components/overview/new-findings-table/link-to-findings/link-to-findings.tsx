"use client";

import { CustomButton } from "@/components/ui/custom";

export const LinkToFindings = () => {
  return (
    <div className="mt-4 flex w-full items-center justify-end">
      <CustomButton
        asLink="/findings?sort=severity,-updated_at&filter[status__in]=FAIL"
        ariaLabel="Go to Findings page"
        variant="solid"
        color="action"
        size="sm"
      >
        Check out on Findings
      </CustomButton>
    </div>
  );
};
