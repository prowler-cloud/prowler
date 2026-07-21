import {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_SOURCE,
  LIGHTHOUSE_PAGE_ID,
  type LighthouseContextFilters,
  type LighthousePageContextItem,
  type LighthousePageId,
} from "@/types/lighthouse-context";

export type LighthousePageSuggestions = readonly [
  string,
  string,
  string,
  string,
];

export interface LighthousePageDefinition {
  id: LighthousePageId;
  label: string;
  match: (pathname: string) => boolean;
  allowedSearchParams: readonly string[];
  suggestions: LighthousePageSuggestions;
  buildPageContext: (
    pathname: string,
    searchParams: URLSearchParams,
  ) => LighthousePageContextItem;
}

interface LighthousePageDefinitionInput {
  id: LighthousePageId;
  label: string;
  match: (pathname: string) => boolean;
  allowedSearchParams: readonly string[];
  suggestions: LighthousePageSuggestions;
}

const PROVIDER_SCOPE_PARAMS = [
  "filter[provider__in]",
  "filter[provider_id__in]",
  "filter[provider_uid]",
  "filter[provider_uid__in]",
  "filter[provider_type__in]",
  "filter[provider]",
  "filter[provider_type]",
  "filter[provider_groups__in]",
] as const;

const COMMON_LIST_PARAMS = [
  "query",
  "search",
  "filter[search]",
  "sort",
] as const;

const GLOBAL_SUGGESTIONS = [
  "Summarize my most critical open findings and what to fix first.",
  "What are my highest-impact compliance gaps right now?",
  "Find risky attack paths and explain the exposure.",
  "How can I improve my cloud security posture today?",
] as const satisfies LighthousePageSuggestions;

const PAGE_DEFINITIONS: readonly LighthousePageDefinition[] = [
  createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.OVERVIEW,
    label: "Overview",
    match: (pathname) => pathname === "/",
    allowedSearchParams: PROVIDER_SCOPE_PARAMS,
    suggestions: [
      "What should I prioritize from this overview?",
      "Explain the visible threat score and its main drivers.",
      "Which accounts or services appear to carry the most risk?",
      "Build a practical security plan for today.",
    ],
  }),
  createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.FINDINGS,
    label: "Findings",
    match: (pathname) => pathname === "/findings",
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      ...COMMON_LIST_PARAMS,
      "filter[region__in]",
      "filter[service__in]",
      "filter[severity__in]",
      "filter[status__in]",
      "filter[delta]",
      "filter[delta__in]",
      "filter[resource_type__in]",
      "filter[category__in]",
      "filter[resource_groups__in]",
      "filter[scan]",
      "filter[scan__in]",
      "filter[scan_id]",
      "filter[scan_id__in]",
      "filter[inserted_at]",
      "filter[muted]",
    ],
    suggestions: [
      "Which visible critical findings need attention first?",
      "Prioritize remediation for the current findings.",
      "Identify likely root causes across these findings.",
      "Create a remediation plan for this findings view.",
    ],
  }),
  createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.RESOURCES,
    label: "Resources",
    match: (pathname) => pathname === "/resources",
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      ...COMMON_LIST_PARAMS,
      "filter[region__in]",
      "filter[service__in]",
      "filter[type__in]",
      "filter[groups__in]",
    ],
    suggestions: [
      "Which visible resources carry the most risk?",
      "Find likely exposures among these resources.",
      "Identify security patterns across the current resources.",
      "Recommend a hardening plan for this resource scope.",
    ],
  }),
  createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.COMPLIANCE_DETAIL,
    label: "Compliance detail",
    match: (pathname) => pathname.startsWith("/compliance/"),
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      "scanId",
      "scan_id",
      "complianceId",
      "section",
      "mode",
      "version",
      "filter[cis_profile_level]",
      "filter[region__in]",
      "filter[status__in]",
    ],
    suggestions: [
      "Which failed requirements need attention first?",
      "Prioritize remediation for this compliance framework.",
      "Which sections are weakest and why?",
      "Create a plan to improve this framework score.",
    ],
  }),
  createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.COMPLIANCE,
    label: "Compliance",
    match: (pathname) => pathname === "/compliance",
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      "tab",
      "scanId",
      "scan_id",
      "framework",
      "version",
      "mode",
      "section",
      "filter[compliance_id]",
      "filter[region__in]",
    ],
    suggestions: [
      "Summarize the most important compliance gaps.",
      "Which frameworks should I prioritize?",
      "Explain the visible compliance score.",
      "Which controls need remediation first?",
    ],
  }),
  createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.ATTACK_PATHS,
    label: "Attack Paths",
    match: (pathname) => pathname.startsWith("/attack-paths"),
    allowedSearchParams: ["scanId", "queryId"],
    suggestions: [
      "Explain the current attack path.",
      "Which nodes are most critical in this graph?",
      "Where should I break this attack path first?",
      "Recommend remediations for the current attack path.",
    ],
  }),
  createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.SCANS,
    label: "Scans",
    match: (pathname) => pathname.startsWith("/scans"),
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      ...COMMON_LIST_PARAMS,
      "tab",
      "scanId",
      "filter[state]",
      "filter[state__in]",
      "filter[trigger]",
    ],
    suggestions: [
      "Summarize recent scan activity.",
      "Which visible scans look problematic?",
      "Explain the most important scan failures.",
      "What should I investigate next from this scans view?",
    ],
  }),
  createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.PROVIDERS,
    label: "Providers",
    match: (pathname) => pathname === "/providers",
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      ...COMMON_LIST_PARAMS,
      "tab",
      "filter[status]",
      "filter[connected]",
    ],
    suggestions: [
      "Which visible providers need attention?",
      "Assess security coverage across these providers.",
      "Which providers may have stale scans?",
      "What should I improve in provider onboarding?",
    ],
  }),
];

const KNOWN_ROUTE_LABELS = {
  alerts: "Alerts",
  integrations: "Integrations",
  mutelist: "Mute list",
  services: "Services",
  workloads: "Workloads",
} as const;

export function normalizeLighthousePath(pathname: string): string {
  const normalized = `/${pathname
    .split("?")[0]
    .split("/")
    .filter(Boolean)
    .map(decodePathSegment)
    .join("/")}`;
  return normalized === "/" ? normalized : normalized.slice(0, 256);
}

export function resolveLighthousePage(
  pathname: string,
): LighthousePageDefinition {
  const normalizedPath = normalizeLighthousePath(pathname);
  return (
    PAGE_DEFINITIONS.find((definition) => definition.match(normalizedPath)) ??
    createFallbackDefinition(normalizedPath)
  );
}

export function buildLighthousePageContext(
  pathname: string,
  searchParams: URLSearchParams,
): LighthousePageContextItem {
  const normalizedPath = normalizeLighthousePath(pathname);
  return resolveLighthousePage(normalizedPath).buildPageContext(
    normalizedPath,
    searchParams,
  );
}

export function getLighthouseScopeKey(pathname: string): string {
  const normalizedPath = normalizeLighthousePath(pathname);
  const page = resolveLighthousePage(normalizedPath);
  return `${page.id}:${normalizedPath}`;
}

function createPageDefinition(
  input: LighthousePageDefinitionInput,
): LighthousePageDefinition {
  return {
    ...input,
    buildPageContext: (pathname, searchParams) => {
      const filters = buildFilters(searchParams, input.allowedSearchParams);
      return {
        kind: LIGHTHOUSE_CONTEXT_KIND.PAGE,
        id: input.id,
        source: LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
        scopeKey: `${input.id}:${pathname}`,
        label: input.label,
        path: pathname,
        ...(Object.keys(filters).length > 0 ? { filters } : {}),
      };
    },
  };
}

function createFallbackDefinition(pathname: string): LighthousePageDefinition {
  const segment = pathname.split("/").filter(Boolean)[0] ?? "overview";
  const label =
    KNOWN_ROUTE_LABELS[segment as keyof typeof KNOWN_ROUTE_LABELS] ??
    toTitleCase(segment);
  return createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.OTHER,
    label,
    match: () => true,
    allowedSearchParams: [],
    suggestions: GLOBAL_SUGGESTIONS,
  });
}

function buildFilters(
  searchParams: URLSearchParams,
  allowedSearchParams: readonly string[],
): LighthouseContextFilters {
  const filters: LighthouseContextFilters = {};
  let remainingValues = 20;

  for (const param of [...allowedSearchParams].sort()) {
    if (remainingValues === 0) break;
    const values = searchParams
      .getAll(param)
      .flatMap((value) => value.split(","))
      .map((value) => value.trim())
      .filter(
        (value) =>
          value.length > 0 && !containsSensitiveLighthouseContextValue(value),
      )
      .map((value) => value.slice(0, 256))
      .slice(0, remainingValues);
    if (values.length === 0) continue;

    const key = toContextFilterKey(param);
    filters[key] = [...(filters[key] ?? []), ...values];
    remainingValues -= values.length;
  }

  return Object.fromEntries(
    Object.entries(filters).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    ),
  );
}

function toContextFilterKey(param: string): string {
  if (!param.startsWith("filter[")) return param === "query" ? "search" : param;
  return param.slice(7, -1).replace(/__in$/, "");
}

export function containsSensitiveLighthouseContextValue(
  value: string,
): boolean {
  return (
    /\b[^\s@]+@[^\s@]+\.[^\s@]+\b/.test(value) ||
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(value) ||
    /\bAKIA[A-Z0-9]{16}\b/.test(value) ||
    /\bbearer\s+\S+/i.test(value) ||
    /\b(?:password|secret|token|credential)\s*[:=]/i.test(value)
  );
}

function toTitleCase(value: string): string {
  if (!value) return "Current page";
  return value
    .split("-")
    .filter(Boolean)
    .map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`)
    .join(" ")
    .slice(0, 256);
}

function decodePathSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}
