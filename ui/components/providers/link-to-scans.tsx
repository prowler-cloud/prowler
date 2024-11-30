"use client";

import { CustomButton } from "@/components/ui/custom";

interface LinkToScansProps {
  providerUid?: string;
}

export const LinkToScans = ({ providerUid }: LinkToScansProps) => {
  return (
    <CustomButton
      asLink={`/scans?filter[provider_uid]=${providerUid}`}
      ariaLabel="Go to Scans page"
      variant="solid"
      color="action"
      size="sm"
    >
      View Scan Jobs
    </CustomButton>
  );
};
