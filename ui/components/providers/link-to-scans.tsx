"use client";

import Link from "next/link";

import { Button } from "@/components/shadcn";

interface LinkToScansProps {
  providerUid?: string;
}

export const LinkToScans = ({ providerUid }: LinkToScansProps) => {
  return (
    <Button asChild variant="link" size="sm" className="text-xs">
      <Link href={`/scans?filter[provider_uid]=${providerUid}`}>
        View Scan Jobs
      </Link>
    </Button>
  );
};
