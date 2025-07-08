"use client";

import { CustomLink } from "@/components/ui/custom";

interface LinkToScansProps {
  providerUid?: string;
}

export const LinkToScans = ({ providerUid }: LinkToScansProps) => {
  return (
    <CustomLink
      href={`/scans?filter[provider_uid]=${providerUid}`}
      ariaLabel="Go to Scans page"
      variant="solid"
      color="action"
      size="sm"
    >
      View Scan Jobs
    </CustomLink>
  );
};
