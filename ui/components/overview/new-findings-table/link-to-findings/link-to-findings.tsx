import Link from "next/link";

import {
  FAIL_FILTER_VALUE,
  NEW_DELTA_FILTER_VALUE,
} from "@/lib/findings-filters";
import { FINDING_GROUPS_FILTERED_SORT } from "@/lib/findings-sort";

const FINDINGS_LINK_HREF = `/findings?sort=${FINDING_GROUPS_FILTERED_SORT}&filter[status__in]=${FAIL_FILTER_VALUE}&filter[delta]=${NEW_DELTA_FILTER_VALUE}`;

export const LinkToFindings = () => {
  return (
    <Link
      href={FINDINGS_LINK_HREF}
      aria-label="Go to Findings page"
      className="text-button-tertiary hover:text-button-tertiary-hover text-sm font-medium transition-colors"
    >
      Check out on Findings
    </Link>
  );
};
