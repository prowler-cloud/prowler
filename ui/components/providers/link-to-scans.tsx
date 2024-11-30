"use client";

import { CustomButton } from "@/components/ui/custom";

export const LinkToScans = () => {
  return (
    <div className="mt-4 flex w-full items-center justify-end">
      <CustomButton
        asLink="/scans"
        ariaLabel="Go to Scans page"
        variant="solid"
        color="action"
        size="md"
      >
        View Scan Jobs
      </CustomButton>
    </div>
  );
};
