"use client";

import Link from "next/link";

import { Button } from "@/components/shadcn";

interface LinkToScansProps {
  hasSchedule: boolean;
  providerUid?: string;
}

export const LinkToScans = ({ hasSchedule, providerUid }: LinkToScansProps) => {
  return (
    <div className="flex items-center gap-1">
      <span className="text-text-neutral-secondary text-sm">
        {hasSchedule ? "Daily" : "None"}
      </span>
      <Button asChild variant="link" size="sm" className="text-xs">
        <Link href={`/scans?filter[provider_uid]=${providerUid}`}>
          View Jobs
        </Link>
      </Button>
    </div>
  );
};
