import { SearchParamsProps } from "@/types";

/** The overview's scope selectors that the issues endpoint also understands. */
export const ISSUE_SCOPE_KEYS = [
  "filter[provider_id__in]",
  "filter[provider_type__in]",
  "filter[provider_groups__in]",
];

export const pickIssueScope = (
  params: SearchParamsProps | undefined | null,
): Record<string, string> =>
  Object.fromEntries(
    ISSUE_SCOPE_KEYS.flatMap((key) => {
      const value = params?.[key];
      return typeof value === "string" && value ? [[key, value]] : [];
    }),
  );

/** The issues route, keeping the overview scope so the counts still match. */
export const issuesHref = (
  scope: Record<string, string>,
  extra: Record<string, string> = {},
) => {
  const query = new URLSearchParams({ ...scope, ...extra }).toString();
  return query ? `/issues?${query}` : "/issues";
};
