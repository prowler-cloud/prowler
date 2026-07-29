import {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_LIMIT,
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
  "Pull my findings, compliance gaps, and attack paths together into one picture. What's my single biggest security risk right now, and how confident are you?",
  "Which of my mute rules are hiding something that now matters — rules written for a resource that changed, or an exception nobody has revisited?",
  "Look at my most serious findings from the last month. Which of them produced no alert from Prowler, and what rule would have caught them?",
  "Turn my top security work into Jira tickets: group related findings into one ticket per root cause, write each so an engineer can act on it without coming back to ask me questions, and tell me which project each should go to.",
] as const satisfies LighthousePageSuggestions;

const PAGE_DEFINITIONS: readonly LighthousePageDefinition[] = [
  createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.OVERVIEW,
    label: "Overview",
    match: (pathname) => pathname === "/",
    allowedSearchParams: PROVIDER_SCOPE_PARAMS,
    suggestions: [
      "What should I prioritize from this overview?",
      "According to the Prowler ThreatScore, what do I need to improve, and why?",
      "Build a practical security plan for today.",
      "What's missing from this dashboard that should worry me — providers not onboarded, regions or services with no scan coverage, checks that never run?",
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
      "Give me the actual remediation for the top failing check here: the commands and IaC changes (of possible and Terraform preferred), the blast radius of applying them, and what to verify afterwards",
      "Severity here is the check's label, not my actual risk. Re-rank these by real exposure, whether the affected resource is internet-facing, production, or holds data; and give me the true top five.",
      "Group these by the underlying change that fixes them, the same IAM policy, module, or baseline; not by check. Which single change clears the most findings?",
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
      "What's the first thing among this resources you'd target in an attack, what would it give you, and how far could you pivot from there?",
      "What does this inventory tell you about how this environment was built, and where does that design create security debt?",
      "Turn this inventory into a per-team action list. Infer likely owners from tags and naming, and give each team their top three fixes.",
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
      "Which requirements here can't be satisfied by scanning at all? Tell me exactly what evidence to collect, who owns it, and what good evidence looks like.",
      "Play the auditor for my weakest section. What will you ask me, what evidence will you want to see, and where am I going to struggle?",
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
      "How much work is it to take my weakest framework to passing? Break each provider account it into a few sprints with what lands first",
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
      "I'm shipping to production. Scan now and tell me if anything regressed versus the last run",
      "Which providers have never been scanned or haven't been scanned recently? Rescan the ones that matter.",
      "Which of my providers have no recurring scan? Tell me which ones should, and set up scheduled scans and with what frequency.",
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
      "What parts of my cloud estate aren't onboarded? Provider accounts that exist but Prowler isn't scanning.",
      "Group this provider accounts by what they're actually for, based on names, tags, and what's running in them. Which of those groupings should exist as provider groups in Prowler but don't?",
      "Which accounts were added recently but never fully configured — no schedule, no groups, no successful scan?",
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

function normalizeLighthousePath(pathname: string): string {
  const normalized = `/${pathname
    .split("?")[0]
    .split("/")
    .filter(Boolean)
    .map(decodePathSegment)
    .join("/")}`;
  return normalized === "/"
    ? normalized
    : normalized.slice(0, LIGHTHOUSE_CONTEXT_LIMIT.STRING_LENGTH);
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
  return buildLighthouseScopeKey(page.id, normalizedPath);
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
        scopeKey: buildLighthouseScopeKey(input.id, pathname),
        label: input.label,
        path: pathname,
        ...(Object.keys(filters).length > 0 ? { filters } : {}),
      };
    },
  };
}

function buildLighthouseScopeKey(
  pageId: LighthousePageId,
  pathname: string,
): string {
  const prefix = `${pageId}:`;
  return `${prefix}${pathname.slice(
    0,
    LIGHTHOUSE_CONTEXT_LIMIT.STRING_LENGTH - prefix.length,
  )}`;
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
  let remainingValues: number = LIGHTHOUSE_CONTEXT_LIMIT.FILTER_VALUES;

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
      .map((value) => value.slice(0, LIGHTHOUSE_CONTEXT_LIMIT.STRING_LENGTH))
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
    containsIpv6Address(value) ||
    /\bAKIA[A-Z0-9]{16}\b/.test(value) ||
    /\bbearer\s+\S+/i.test(value) ||
    /\b(?:password|secret|token|credential)\s*[:=]/i.test(value)
  );
}

function containsIpv6Address(value: string): boolean {
  return value
    .split(/[^0-9A-Fa-f:]+/)
    .some((candidate) => isIpv6AddressCandidate(candidate));
}

function isIpv6AddressCandidate(candidate: string): boolean {
  if (!candidate.includes(":") || candidate.includes(":::")) return false;

  const compressedParts = candidate.split("::");
  if (compressedParts.length > 2) return false;

  const segments = candidate.split(":").filter(Boolean);
  if (segments.some((segment) => segment.length > 4)) return false;

  return compressedParts.length === 2
    ? segments.length < 8
    : segments.length === 8;
}

function toTitleCase(value: string): string {
  if (!value) return "Current page";
  return value
    .split("-")
    .filter(Boolean)
    .map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`)
    .join(" ")
    .slice(0, LIGHTHOUSE_CONTEXT_LIMIT.STRING_LENGTH);
}

function decodePathSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}
