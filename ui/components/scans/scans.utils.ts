import {
  DEFAULT_SCAN_JOBS_TAB,
  SCAN_JOBS_TAB,
  SCAN_STATE,
  SCAN_TRIGGER,
  type ScanAttributes,
  type ScanFindingsSummary,
  type ScanJobsTab,
  type ScanProps,
  type ScanState,
  type ScanTrigger,
} from "@/types";

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
const SCAN_JOBS_TAB_STATES: Record<ScanJobsTab, ScanState[]> = {
  [SCAN_JOBS_TAB.ACTIVE]: [SCAN_STATE.AVAILABLE, SCAN_STATE.EXECUTING],
  [SCAN_JOBS_TAB.COMPLETED]: [
    SCAN_STATE.COMPLETED,
    SCAN_STATE.FAILED,
    SCAN_STATE.CANCELLED,
  ],
  [SCAN_JOBS_TAB.SCHEDULED]: [SCAN_STATE.SCHEDULED],
};

export interface ScanTriggerFilterOption {
  value: typeof ALL_VALUE | ScanTrigger;
  label: string;
}

export interface ScanStatusFilterOption {
  value: typeof ALL_VALUE | ScanState;
  label: string;
}

export function getScanTriggerFilterOptions(
  isCloudEnvironment: boolean,
): ScanTriggerFilterOption[] {
  const options: ScanTriggerFilterOption[] = [
    { value: ALL_VALUE, label: "All Types" },
    { value: SCAN_TRIGGER.MANUAL, label: "Manual" },
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

function parseStateFilter(value?: string | string[]): ScanState[] {
  const rawValue = Array.isArray(value) ? value.join(",") : value;
  if (!rawValue || rawValue === ALL_VALUE) return [];

  return rawValue
    .split(",")
    .filter((item): item is ScanState =>
      Object.values(SCAN_STATE).includes(item as ScanState),
    );
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
  stateFilter?: string | string[],
): Record<string, string> {
  const selectedStates = parseStateFilter(stateFilter);
  const allowedStates = SCAN_JOBS_TAB_STATES[tab];
  const matchingStates = selectedStates.filter((state) =>
    allowedStates.includes(state),
  );

  if (matchingStates.length === 0) return { ...SCAN_JOBS_TAB_FILTERS[tab] };

  return { "filter[state__in]": matchingStates.join(",") };
}

export function getScanAlias(scan: ScanProps): string {
  if (scan.attributes.trigger === SCAN_TRIGGER.SCHEDULED)
    return "scheduled scan";
  return scan.attributes.name?.trim() || "-";
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
  if (trigger === "manual") return "Manual";
  if (trigger === "imported") return "Imported";
  return "-";
}

export function getScanStatusLabel(state?: ScanState | string): string {
  if (state === "available") return "Queued";
  if (!state) return "-";
  return state.charAt(0).toUpperCase() + state.slice(1);
}

export function getScanStatusFilterOptions(
  tab: ScanJobsTab,
): ScanStatusFilterOption[] {
  return [
    { value: ALL_VALUE, label: "All Statuses" },
    ...SCAN_JOBS_TAB_STATES[tab].map((state) => ({
      value: state,
      label: getScanStatusLabel(state),
    })),
  ];
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
