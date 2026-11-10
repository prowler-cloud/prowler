const REALTIME_PATH = "/realtime";
const REALTIME_CONFIGURATION_PATH = "/realtime/configuration";

/** Dashboard tabs, in display order (`?tab=`). */
export const REALTIME_TAB = {
  OVERVIEW: "overview",
  DETECTIONS: "detections",
  REMEDIATION: "remediation",
  STREAM: "stream",
  FINDINGS: "findings",
  COST: "cost",
} as const;
export type RealtimeTab = (typeof REALTIME_TAB)[keyof typeof REALTIME_TAB];

export const REALTIME_TAB_LABELS: Record<RealtimeTab, string> = {
  [REALTIME_TAB.OVERVIEW]: "Overview",
  [REALTIME_TAB.DETECTIONS]: "Detections",
  [REALTIME_TAB.REMEDIATION]: "Remediation",
  [REALTIME_TAB.STREAM]: "Event stream",
  [REALTIME_TAB.FINDINGS]: "Prioritized findings",
  [REALTIME_TAB.COST]: "Cost",
};

export const REALTIME_TAB_ORDER = Object.values(REALTIME_TAB);

/** Search params the Realtime pages read. Filters use `filter[...]`. */
export const REALTIME_PARAM = {
  PROVIDER: "provider",
  TAB: "tab",
  /** Detection open in the side panel. */
  DETECTION: "detection",
  /** Action open in the side panel. */
  ACTION: "action",
  /** Cost anomaly (`<service>|<region>`) open in the side panel. */
  ANOMALY: "anomaly",
  /** Event stream: show read-only calls too. */
  ALL_EVENTS: "allEvents",
  /** Configuration section to open. */
  SECTION: "section",
} as const;

export type RealtimeSearchParams = Record<
  string,
  string | string[] | undefined
>;

export const firstParam = (
  params: RealtimeSearchParams,
  key: string,
): string | undefined => {
  const value = params[key];
  return Array.isArray(value) ? value[0] : value;
};

/** A comma-separated `filter[key]` value as a list. */
export const listParam = (
  params: RealtimeSearchParams,
  key: string,
): string[] =>
  (firstParam(params, key) ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

export const pageParam = (params: RealtimeSearchParams): number => {
  const page = Number.parseInt(firstParam(params, "page") ?? "1", 10);
  return Number.isFinite(page) && page > 0 ? page : 1;
};

export const pageSizeParam = (
  params: RealtimeSearchParams,
  fallback = 20,
): number => {
  const size = Number.parseInt(firstParam(params, "pageSize") ?? "", 10);
  return Number.isFinite(size) && size > 0 ? Math.min(size, 100) : fallback;
};

export const parseTab = (value: string | undefined): RealtimeTab =>
  REALTIME_TAB_ORDER.includes(value as RealtimeTab)
    ? (value as RealtimeTab)
    : REALTIME_TAB.OVERVIEW;

const withQuery = (path: string, query: Record<string, string | undefined>) => {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  const search = params.toString();
  return search ? `${path}?${search}` : path;
};

/** A dashboard URL. Filters and panels of other tabs are dropped. */
export const realtimeHref = (
  providerId: string | undefined,
  tab: RealtimeTab = REALTIME_TAB.OVERVIEW,
  extra: Record<string, string | undefined> = {},
): string =>
  withQuery(REALTIME_PATH, {
    [REALTIME_PARAM.PROVIDER]: providerId,
    [REALTIME_PARAM.TAB]: tab === REALTIME_TAB.OVERVIEW ? undefined : tab,
    ...extra,
  });

export const configurationHref = (
  providerId: string | undefined,
  section?: string,
): string =>
  withQuery(REALTIME_CONFIGURATION_PATH, {
    [REALTIME_PARAM.PROVIDER]: providerId,
    [REALTIME_PARAM.SECTION]: section,
  });

/** The Lighthouse AI chat route (the sidebar's "Lighthouse AI" entry). */
export const LIGHTHOUSE_CHAT_PATH = "/lighthouse";

/** Failing findings of one check in the Findings page. */
export const checkFindingsHref = (checkId: string): string =>
  withQuery("/findings", {
    "filter[check_id__in]": checkId,
    "filter[status__in]": "FAIL",
    "filter[muted]": "false",
  });
