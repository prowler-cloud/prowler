/**
 * Shared filter constants and helpers for findings-shaped endpoints.
 *
 * Pairs with `lib/findings-sort.ts` (sort tokens). This module covers the
 * filter side of the same query language.
 */

// ---------------------------------------------------------------------------
// Filter values
// ---------------------------------------------------------------------------

/**
 * The "FAIL" status value as it crosses the wire to the API. Used in both
 * `filter[status]` (single) and `filter[status__in]` (CSV) form.
 *
 * NOTE: this is a bare value, not a full enum. The broader Status/Delta
 * enum migration is intentionally out of scope here — see PR follow-up.
 */
export const FAIL_FILTER_VALUE = "FAIL";

/**
 * The "new" delta value. Used in `filter[delta]` and `filter[delta__in]`.
 */
export const NEW_DELTA_FILTER_VALUE = "new";

/**
 * Values accepted by `filter[muted]`.
 *
 * - `EXCLUDE` ("false"): the API hides muted findings (default UI behaviour).
 * - `INCLUDE` ("include"): a sentinel that the API treats as "show all
 *   regardless of muted state". This is NOT the literal string "true" — the
 *   server route ignores invalid values which conveniently bypasses the
 *   filter.
 */
export const MUTED_FILTER = {
  EXCLUDE: "false",
  INCLUDE: "include",
} as const;

export type MutedFilterValue = (typeof MUTED_FILTER)[keyof typeof MUTED_FILTER];

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/**
 * Drill-down preset: "FAIL findings, hide muted". Mutates `params` in place.
 *
 * Repeated 6+ times across overview widgets that link to /findings
 * (attack-surface card, sankey, severity-over-time, risk-radar, risk-plot,
 * etc). Centralising avoids drift if product later adds, say, `delta=new`
 * to all drill-downs.
 */
export function applyFailNonMutedFilters(params: URLSearchParams): void {
  params.set("filter[status__in]", FAIL_FILTER_VALUE);
  params.set("filter[muted]", MUTED_FILTER.EXCLUDE);
}

// ---------------------------------------------------------------------------
// Filter parsing
// ---------------------------------------------------------------------------

/**
 * Splits a JSON:API CSV filter value into clean string tokens.
 *
 * Accepts both string and string[] inputs because Next.js `searchParams`
 * surface either form depending on whether the key appears once or multiple
 * times in the URL. Returns trimmed, non-empty tokens in input order.
 *
 * Previously duplicated in three call sites
 * (actions/finding-groups, components/findings/table/inline-resource-container,
 * implicitly inside lib/findings-groups). Single source now.
 */
export function splitCsvFilterValues(
  value: string | string[] | undefined,
): string[] {
  if (Array.isArray(value)) {
    return value
      .flatMap((item) => item.split(","))
      .map((item) => item.trim())
      .filter(Boolean);
  }

  if (typeof value === "string") {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  return [];
}

/**
 * True when the caller has opted into seeing muted findings via either the
 * `filter[muted]=include` shorthand or a multi-value variant.
 *
 * Previously duplicated in actions/finding-groups and
 * components/findings/table/inline-resource-container.
 */
export function includesMutedFindings(
  filters: Record<string, string | string[] | undefined>,
): boolean {
  const mutedFilter = filters["filter[muted]"];

  if (Array.isArray(mutedFilter)) {
    return mutedFilter.includes(MUTED_FILTER.INCLUDE);
  }

  return mutedFilter === MUTED_FILTER.INCLUDE;
}
