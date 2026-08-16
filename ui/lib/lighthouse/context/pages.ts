import {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_LIMIT,
  LIGHTHOUSE_CONTEXT_SOURCE,
  LIGHTHOUSE_PAGE_ID,
  type LighthouseContextFilters,
  type LighthousePageDefinitionInput,
  type LighthousePageContextItem,
  type LighthousePageId,
  type LighthousePageSuggestions,
} from "@/types/lighthouse-context";

import {
  LIGHTHOUSE_GLOBAL_SUGGESTIONS,
  LIGHTHOUSE_PAGE_DEFINITION_INPUTS,
} from "./pages.constants";

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

const PAGE_DEFINITIONS: readonly LighthousePageDefinition[] =
  LIGHTHOUSE_PAGE_DEFINITION_INPUTS.map(createPageDefinition);

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
  const label = toTitleCase(segment);
  return createPageDefinition({
    id: LIGHTHOUSE_PAGE_ID.OTHER,
    label,
    match: () => true,
    allowedSearchParams: [],
    suggestions: LIGHTHOUSE_GLOBAL_SUGGESTIONS,
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
