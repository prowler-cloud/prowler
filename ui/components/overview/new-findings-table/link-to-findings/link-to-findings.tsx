"use client";

import { CustomLink } from "@/components/ui/custom";

export const LinkToFindings = () => {
  return (
    <div className="mt-4 flex w-full items-center justify-end">
      <CustomLink
        href="/findings?sort=severity,-inserted_at&filter[status__in]=FAIL&filter[delta__in]=new"
        ariaLabel="Go to Findings page"
        variant="solid"
        color="action"
        size="sm"
      >
        Check out on Findings
      </CustomLink>
    </div>
  );
};
