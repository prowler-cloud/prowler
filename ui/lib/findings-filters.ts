/**
 * Shared helpers for findings filter handling.
 *
 * The `/findings` SSR page and the finding-group resource drill-down both
 * need to hide muted findings by default — unless the user has opted in via
 * the "include muted findings" checkbox. Keeping that default in one place
 * prevents surfaces from drifting.
 */

export const MUTED_FILTER = {
  /** Wire value sent to the API to exclude muted findings. */
  EXCLUDE: "false",
  /**
   * Sentinel value that tells the API to return both muted and non-muted
   * findings. The checkbox writes this to the URL when the user opts in.
   */
  INCLUDE: "include",
} as const;

export type MutedFilterValue = (typeof MUTED_FILTER)[keyof typeof MUTED_FILTER];

/**
 * Returns a new filter object with the default muted behaviour applied:
 * hide muted findings unless the caller already set `filter[muted]`.
 *
 * The default is spread BEFORE the caller filters so any explicit value
 * (including `"false"` or the `"include"` opt-in) wins.
 */
export function applyDefaultMutedFilter<
  T extends Record<string, string | string[] | undefined>,
>(filters: T): T {
  return {
    "filter[muted]": MUTED_FILTER.EXCLUDE,
    ...filters,
  };
}
