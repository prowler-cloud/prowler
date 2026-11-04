import { adaptFindingGroupsResponse } from "@/actions/finding-groups/finding-groups.adapter";
import { getActiveStatusFilter } from "@/lib/findings-groups";
import {
  FINDING_STATUS,
  SEVERITY,
  type FindingStatus,
  SearchParamsProps,
} from "@/types/components";
import type { ProviderProps } from "@/types/providers";

import {
  SAMPLE_ACCOUNT,
  SAMPLE_CHECKS,
  type SampleCheck,
} from "./sample-dataset";
import {
  matchesSampleFindingFilters,
  pickSampleFindingFilters,
  SAMPLE_FINDINGS,
  SAMPLE_ID_PREFIX,
  type SampleFinding,
} from "./sample-records";

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

// Counts come from the matching records, so a filtered group adds up.
const toFindingGroupItem = (
  check: SampleCheck,
  findings: SampleFinding[],
): SampleFindingGroupItem => {
  const failed = findings.filter(
    (finding) => finding.status === FINDING_STATUS.FAIL,
  ).length;
  const passed = findings.length - failed;
  const newFailed = findings.filter(
    (finding) =>
      finding.status === FINDING_STATUS.FAIL && finding.delta === "new",
  ).length;
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
      resources_total: findings.length,
      resources_fail: failed,
      pass_count: passed,
      fail_count: failed,
      muted_count: 0,
      new_count: newFailed,
      changed_count: 0,
      new_fail_count: newFailed,
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
  "filter[resource_groups__in]": (check) => check.resourceGroup,
};

/** The sample groups the URL filters ask for, and the filters for their drill-downs. */
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
  const findingFilters = pickSampleFindingFilters(searchParams);
  const findingsByCheck = new Map<string, SampleFinding[]>();
  for (const finding of SAMPLE_FINDINGS) {
    if (statuses && !statuses.has(finding.status)) continue;
    if (!matchesSampleFindingFilters(finding, findingFilters)) continue;
    const checkFindings = findingsByCheck.get(finding.check.checkId) ?? [];
    checkFindings.push(finding);
    findingsByCheck.set(finding.check.checkId, checkFindings);
  }
  const checks = SAMPLE_CHECKS.filter(
    (check) =>
      findingsByCheck.has(check.checkId) &&
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
  const resourceFilters: Record<string, string> = {
    ...(statuses
      ? { "filter[status__in]": Array.from(statuses).join(",") }
      : {}),
    ...findingFilters,
  };
  return {
    groups: adaptFindingGroupsResponse({
      data: checks.map((check) =>
        toFindingGroupItem(check, findingsByCheck.get(check.checkId) ?? []),
      ),
    }),
    resourceFilters,
  };
};

const unique = (values: (string | undefined)[]) =>
  Array.from(
    new Set(values.filter((value): value is string => Boolean(value))),
  ).sort();

/** Filter bar options, derived from the records the sample filters match. */
export const SAMPLE_FINDING_FILTER_OPTIONS = {
  regions: unique(SAMPLE_FINDINGS.map((finding) => finding.resource.region)),
  services: unique(SAMPLE_CHECKS.map((check) => check.service)),
  resourceTypes: unique(
    SAMPLE_FINDINGS.map((finding) => finding.resource.type),
  ),
  categories: unique(SAMPLE_CHECKS.map((check) => check.attackSurface)),
  groups: unique(SAMPLE_CHECKS.map((check) => check.resourceGroup)),
};

/** The sample account, so the provider filter can select it. */
export const SAMPLE_FILTER_PROVIDER: ProviderProps = {
  id: SAMPLE_ACCOUNT.providerId,
  type: "providers",
  attributes: {
    provider: "aws",
    is_dynamic: false,
    uid: SAMPLE_ACCOUNT.uid,
    alias: SAMPLE_ACCOUNT.alias,
    status: "completed",
    resources: SAMPLE_FINDINGS.length,
    connection: { connected: true, last_checked_at: SAMPLE_ACCOUNT.scannedAt },
    scanner_args: {
      only_logs: false,
      excluded_checks: [],
      aws_retries_max_attempts: 3,
    },
    inserted_at: SAMPLE_ACCOUNT.scannedAt,
    updated_at: SAMPLE_ACCOUNT.scannedAt,
    created_by: { object: "user", id: `${SAMPLE_ID_PREFIX}user` },
  },
  relationships: {
    secret: { data: null },
    provider_groups: { meta: { count: 0 }, data: [] },
  },
};
