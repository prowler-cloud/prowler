import { adaptFindingGroupsResponse } from "@/actions/finding-groups/finding-groups.adapter";
import type { SearchParamsProps } from "@/types/components";

import {
  SAMPLE_ACCOUNT,
  SAMPLE_FAILED_CHECKS,
  type SampleCheck,
} from "./sample-dataset";

// Finding groups derived from SAMPLE_CHECKS, in the API response shape so they
// run through the same adapter as real data.

interface SampleFindingGroupAttributes {
  check_id: string;
  check_title: string;
  check_description: null;
  severity: string;
  status: "FAIL";
  muted: false;
  impacted_providers: string[];
  resources_total: number;
  resources_fail: number;
  pass_count: number;
  fail_count: number;
  muted_count: number;
  new_count: number;
  changed_count: number;
  new_fail_count: number;
  first_seen_at: string;
  last_seen_at: string;
  failing_since: string;
}

interface SampleFindingGroupItem {
  type: "finding-groups";
  id: string;
  attributes: SampleFindingGroupAttributes;
}

const toFindingGroupItem = (check: SampleCheck): SampleFindingGroupItem => ({
  type: "finding-groups",
  id: check.checkId,
  attributes: {
    check_id: check.checkId,
    check_title: check.title,
    check_description: null,
    severity: check.severity,
    status: "FAIL",
    muted: false,
    impacted_providers: ["aws"],
    resources_total: check.failed + check.passed,
    resources_fail: check.failed,
    pass_count: check.passed,
    fail_count: check.failed,
    muted_count: 0,
    new_count: check.newFailed,
    changed_count: 0,
    new_fail_count: check.newFailed,
    first_seen_at: SAMPLE_ACCOUNT.scannedAt,
    last_seen_at: SAMPLE_ACCOUNT.scannedAt,
    failing_since: SAMPLE_ACCOUNT.scannedAt,
  },
});

/** The filters the Overview drill-downs set, matched the way the API would. */
const SAMPLE_GROUP_FILTERS: Record<
  string,
  (check: SampleCheck) => string | undefined
> = {
  "filter[severity__in]": (check) => check.severity,
  "filter[service__in]": (check) => check.service,
  "filter[category__in]": (check) => check.attackSurface,
  // Every sample group fails.
  "filter[status__in]": () => "FAIL",
};

/** The sample groups an Overview link asked for, and whether any filter applied. */
export const filterSampleFindingGroups = (searchParams: SearchParamsProps) => {
  const active = Object.entries(SAMPLE_GROUP_FILTERS).flatMap(
    ([key, field]) => {
      const value = searchParams[key];
      return typeof value === "string" && value
        ? [{ field, accepted: value.split(",") }]
        : [];
    },
  );
  const checks = SAMPLE_FAILED_CHECKS.filter((check) =>
    active.every(({ field, accepted }) => {
      const actual = field(check);
      return actual !== undefined && accepted.includes(actual);
    }),
  );
  return {
    groups: adaptFindingGroupsResponse({
      data: checks.map(toFindingGroupItem),
    }),
    filtered: active.length > 0,
  };
};
