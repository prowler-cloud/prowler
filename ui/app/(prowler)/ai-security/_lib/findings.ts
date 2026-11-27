/** Every AI check carries this category, whatever provider it belongs to. */
const AI_CATEGORY = { "filter[category__in]": "gen-ai" };

/** The unmuted AI findings in the page's scope, failed ones unless the filters say otherwise. */
export const aiFindingsHref = (
  scope: Record<string, string>,
  filters: Record<string, string> = {},
) =>
  `/findings?${new URLSearchParams({
    ...AI_CATEGORY,
    "filter[status__in]": "FAIL",
    "filter[muted]": "false",
    ...scope,
    ...filters,
  })}`;
