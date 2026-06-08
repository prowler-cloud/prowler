"use client";

import Link from "next/link";

import { Button } from "@/components/shadcn";

interface LinkToScansProps {
  hasSchedule: boolean;
  providerUid?: string;
}

export const LinkToScans = ({ hasSchedule, providerUid }: LinkToScansProps) => {
  // Match the key the scans filter bar binds to (`provider_uid__in`) so the
  // provider is pre-selected, and encode UIDs with URL-unsafe chars (e.g.
  // GitHub UIDs like https://github.com/org/repo).
  const scansHref = `/scans?${new URLSearchParams({
    "filter[provider_uid__in]": providerUid ?? "",
  }).toString()}`;

  return (
    <div className="flex items-center gap-1">
      <span className="text-text-neutral-secondary text-sm">
        {hasSchedule ? "Daily" : "None"}
      </span>
      <Button asChild variant="link" size="sm" className="text-xs">
        <Link href={scansHref}>View Jobs</Link>
      </Button>
    </div>
  );
};
