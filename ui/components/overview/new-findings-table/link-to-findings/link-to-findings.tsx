"use client";

import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";
import { FINDING_GROUPS_FILTERED_SORT } from "@/lib";

// /findings renders the finding-groups view (Family B in lib/findings-sort.ts):
// status/severity are remapped to weighted integer columns, so DESC is
// required and `inserted_at` is not a valid sort key — use `last_seen_at`.
const FINDINGS_LINK_HREF = `/findings?sort=${FINDING_GROUPS_FILTERED_SORT}&filter[status__in]=FAIL&filter[delta__in]=new`;

export const LinkToFindings = () => {
  return (
    <div className="mt-4 flex w-full items-center justify-end">
      <Button asChild variant="default" size="sm">
        <Link href={FINDINGS_LINK_HREF} aria-label="Go to Findings page">
          Check out on Findings
        </Link>
      </Button>
    </div>
  );
};
