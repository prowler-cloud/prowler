import { adaptFindingGroupsResponse } from "@/actions/finding-groups/finding-groups.adapter";
import { getActiveStatusFilter } from "@/lib/findings-groups";
import {
  FINDING_STATUS,
  SEVERITY,
  type FindingStatus,
  SearchParamsProps,
} from "@/types/components";

import {
  SAMPLE_ACCOUNT,
  SAMPLE_CHECKS,
  type SampleCheck,
} from "./sample-dataset";
import { SAMPLE_ID_PREFIX } from "./sample-records";

// Finding groups derived from SAMPLE_CHECKS, in the API response shape so they
// run through the same adapter as real data.

interface SampleFindingGroupAttributes {
  check_id: string;
  check_title: string;
  check_description: null;
  severity: string;
  status: FindingStatus;
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

const toFindingGroupItem = (
  check: SampleCheck,
  statuses: Set<FindingStatus> | null,
): SampleFindingGroupItem => {
  const failed =
    !statuses || statuses.has(FINDING_STATUS.FAIL) ? check.failed : 0;
  const passed =
    !statuses || statuses.has(FINDING_STATUS.PASS) ? check.passed : 0;
  return {
    type: "finding-groups",
    // The sample prefix keeps the group out of Lighthouse context.
    id: `${SAMPLE_ID_PREFIX}group-${check.checkId}`,
    attributes: {
      check_id: check.checkId,
      check_title: check.title,
      check_description: null,
      severity: check.severity,
      status: failed > 0 ? FINDING_STATUS.FAIL : FINDING_STATUS.PASS,
      muted: false,
      impacted_providers: ["aws"],
      resources_total: failed + passed,
      resources_fail: failed,
      pass_count: passed,
      fail_count: failed,
      muted_count: 0,
      new_count: failed > 0 ? check.newFailed : 0,
      changed_count: 0,
      new_fail_count: failed > 0 ? check.newFailed : 0,
      first_seen_at: SAMPLE_ACCOUNT.scannedAt,
      last_seen_at: SAMPLE_ACCOUNT.scannedAt,
      failing_since: SAMPLE_ACCOUNT.scannedAt,
    },
  };
};

/** The filters the Overview drill-downs set, matched the way the API would. */
const SAMPLE_GROUP_FILTERS: Record<
  string,
  (check: SampleCheck) => string | undefined
> = {
  "filter[severity__in]": (check) => check.severity,
  "filter[service__in]": (check) => check.service,
  "filter[category__in]": (check) => check.attackSurface,
  "filter[check_id__in]": (check) => check.checkId,
};

/** The sample groups an Overview link asked for, and whether any filter applied. */
export const filterSampleFindingGroups = (searchParams: SearchParamsProps) => {
  const statuses = getActiveStatusFilter(searchParams);
  const query = searchParams["filter[search]"];
  const search = typeof query === "string" ? query.trim().toLowerCase() : "";
  const active = Object.entries(SAMPLE_GROUP_FILTERS).flatMap(
    ([key, field]) => {
      const value = searchParams[key];
      return typeof value === "string" && value
        ? [{ field, accepted: value.split(",") }]
        : [];
    },
  );
  const checks = SAMPLE_CHECKS.filter(
    (check) =>
      (!statuses ||
        (statuses.has(FINDING_STATUS.FAIL) && check.failed > 0) ||
        (statuses.has(FINDING_STATUS.PASS) && check.passed > 0)) &&
      (!search ||
        `${check.checkId} ${check.title}`.toLowerCase().includes(search)) &&
      active.every(({ field, accepted }) => {
        const actual = field(check);
        return actual !== undefined && accepted.includes(actual);
      }),
  );
  const sort = searchParams.sort;
  if (typeof sort === "string") {
    const descending = sort.startsWith("-");
    const field = descending ? sort.slice(1) : sort;
    const severityOrder = Object.values(SEVERITY);
    if (field === "check_id" || field === "severity") {
      checks.sort((a, b) => {
        const comparison =
          field === "check_id"
            ? a.checkId.localeCompare(b.checkId)
            : severityOrder.indexOf(a.severity) -
              severityOrder.indexOf(b.severity);
        return descending ? -comparison : comparison;
      });
    }
  }
  const resourceFilters: Record<string, string> = statuses
    ? { "filter[status__in]": Array.from(statuses).join(",") }
    : {};
  return {
    groups: adaptFindingGroupsResponse({
      data: checks.map((check) => toFindingGroupItem(check, statuses)),
    }),
    filtered: active.length > 0 || statuses !== null || Boolean(search),
    resourceFilters,
  };
};
