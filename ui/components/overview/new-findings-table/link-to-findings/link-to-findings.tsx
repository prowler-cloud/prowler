"use client";

import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";

export const LinkToFindings = () => {
  return (
    <div className="mt-4 flex w-full items-center justify-end">
      <Button asChild variant="default" size="sm">
        <Link
          href="/findings?sort=severity,-inserted_at&filter[status__in]=FAIL&filter[delta__in]=new"
          aria-label="Go to Findings page"
        >
          Check out on Findings
        </Link>
      </Button>
    </div>
  );
};
