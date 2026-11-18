/** Every AI check carries this category, whatever provider it belongs to. */
const AI_CATEGORY = { "filter[category__in]": "gen-ai" };

/** The unmuted AI findings, failed ones unless the filters say otherwise. */
export const aiFindingsHref = (filters: Record<string, string> = {}) =>
  `/findings?${new URLSearchParams({
    ...AI_CATEGORY,
    "filter[status__in]": "FAIL",
    "filter[muted]": "false",
    ...filters,
  })}`;

export const aiResourcesHref = (filters: Record<string, string> = {}) =>
  `/resources?${new URLSearchParams({ ...AI_CATEGORY, ...filters })}`;
