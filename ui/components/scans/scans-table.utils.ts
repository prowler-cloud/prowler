import {
  SCAN_STATE,
  SCAN_TRIGGER,
  type ScanAttributes,
  type ScanProps,
  type ScanState,
  type ScanTrigger,
} from "@/types";

export const SCAN_JOBS_TAB = {
  ACTIVE: "active",
  COMPLETED: "completed",
  SCHEDULED: "scheduled",
} as const;

export type ScanJobsTab = (typeof SCAN_JOBS_TAB)[keyof typeof SCAN_JOBS_TAB];

export const DEFAULT_SCAN_JOBS_TAB: ScanJobsTab = SCAN_JOBS_TAB.ACTIVE;

export interface ScanFindingsSummary {
  fail: number;
  pass: number;
  failNew?: number;
  passNew?: number;
}

export const SCAN_TAB_LABELS: Record<ScanJobsTab, string> = {
  [SCAN_JOBS_TAB.ACTIVE]: "Active Scans",
  [SCAN_JOBS_TAB.COMPLETED]: "Completed Scans",
  [SCAN_JOBS_TAB.SCHEDULED]: "Scheduled Scans",
};

const SCAN_JOBS_TAB_FILTERS: Record<ScanJobsTab, Record<string, string>> = {
  [SCAN_JOBS_TAB.ACTIVE]: {
    "filter[state__in]": `${SCAN_STATE.AVAILABLE},${SCAN_STATE.EXECUTING}`,
  },
  [SCAN_JOBS_TAB.COMPLETED]: {
    "filter[state__in]": [
      SCAN_STATE.COMPLETED,
      SCAN_STATE.FAILED,
      SCAN_STATE.CANCELLED,
    ].join(","),
  },
  [SCAN_JOBS_TAB.SCHEDULED]: {
    "filter[state__in]": SCAN_STATE.SCHEDULED,
  },
};

export const SCAN_STATE_FILTER_KEYS = [
  "filter[state]",
  "filter[state__in]",
] as const;

const ALL_VALUE = "all";

export interface ScanTriggerFilterOption {
  value: typeof ALL_VALUE | ScanTrigger;
  label: string;
}

export function getScanTriggerFilterOptions(
  isCloudEnvironment: boolean,
): ScanTriggerFilterOption[] {
  const options: ScanTriggerFilterOption[] = [
    { value: ALL_VALUE, label: "All Types" },
    { value: SCAN_TRIGGER.MANUAL, label: "Single" },
    { value: SCAN_TRIGGER.SCHEDULED, label: "Scheduled" },
  ];

  if (isCloudEnvironment) {
    options.push({ value: SCAN_TRIGGER.IMPORTED, label: "Imported" });
  }

  return options;
}

export function isScanStateFilterKey(key: string): boolean {
  return SCAN_STATE_FILTER_KEYS.some((filterKey) => filterKey === key);
}

export function getScanJobsTab(value?: string | string[]): ScanJobsTab {
  const rawValue = Array.isArray(value) ? value[0] : value;
  const tabs = Object.values(SCAN_JOBS_TAB);

  return tabs.includes(rawValue as ScanJobsTab)
    ? (rawValue as ScanJobsTab)
    : DEFAULT_SCAN_JOBS_TAB;
}

export function getScanJobsTabFilters(
  tab: ScanJobsTab,
): Record<string, string> {
  return { ...SCAN_JOBS_TAB_FILTERS[tab] };
}

export function getScanAlias(scan: ScanProps): string {
  const name = scan.attributes.name?.trim();
  if (!name) return "-";
  if (name === "Daily scheduled scan") return "scheduled scan";
  return name;
}

export function formatScanDuration(duration?: number | null): string {
  if (duration === null || duration === undefined || duration < 0) return "-";

  const totalSeconds = Math.round(duration);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;

  if (hours > 0) return `${hours}h ${remainingMinutes}m ${seconds}s`;
  if (minutes > 0) return `${minutes} min ${seconds} sec`;
  return `${seconds} sec`;
}

export function getScanScheduleLabel(trigger?: ScanTrigger | string): string {
  if (trigger === "scheduled") return "Scheduled";
  if (trigger === "manual") return "Single";
  if (trigger === "imported") return "Imported";
  return "-";
}

export function getScanStatusLabel(state?: ScanState | string): string {
  if (state === "available") return "Queued";
  if (!state) return "-";
  return state.charAt(0).toUpperCase() + state.slice(1);
}

function getNumericValue(
  source: Record<string, unknown>,
  keys: string[],
): number | undefined {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }

  return undefined;
}

export function getScanFindingsSummary(
  attributes: ScanAttributes,
): ScanFindingsSummary | null {
  const root = attributes as unknown as Record<string, unknown>;
  const nested =
    typeof root.findings === "object" && root.findings !== null
      ? (root.findings as Record<string, unknown>)
      : {};
  const source = { ...root, ...nested };

  const fail = getNumericValue(source, [
    "fail",
    "failed",
    "failed_findings",
    "fail_findings",
  ]);
  const pass = getNumericValue(source, [
    "pass",
    "passed",
    "passed_findings",
    "pass_findings",
  ]);

  if (fail === undefined || pass === undefined) return null;

  return {
    fail,
    pass,
    failNew: getNumericValue(source, ["fail_new", "new_failed_findings"]),
    passNew: getNumericValue(source, ["pass_new", "new_passed_findings"]),
  };
}
