"use client";

import { CustomButton } from "@/components/ui/custom";

interface LinkToComplianceProps {
  scanId?: string;
  isDisabled?: boolean;
}

export const LinkToComplianceFromScan = ({
  scanId,
  isDisabled,
}: LinkToComplianceProps) => {
  return (
    <CustomButton
      asLink={`/compliance?scanId=${scanId}`}
      ariaLabel="Go to Compliance page"
      variant="ghost"
      className="text-xs font-medium text-default-500 hover:text-primary disabled:opacity-30"
      size="sm"
      isDisabled={isDisabled}
    >
      See Compliance
    </CustomButton>
  );
};
