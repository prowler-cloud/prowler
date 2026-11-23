import type { RealtimePage } from "@/app/(prowler)/realtime/_types";
import type { MetaDataProps } from "@/types";

interface LocalPageOptions<T> {
  /** Rows that survive the URL filters; all rows when omitted. */
  keep?: (item: T) => boolean;
  page: number;
  pageSize: number;
}

/** Filter and paginate a list held in memory (sample data, ranked findings). */
export const localPage = <T>(
  items: T[],
  { keep, page, pageSize }: LocalPageOptions<T>,
): RealtimePage<T> => {
  const kept = keep ? items.filter(keep) : items;
  const pages = Math.max(1, Math.ceil(kept.length / pageSize));
  const current = Math.min(Math.max(page, 1), pages);
  return {
    items: kept.slice((current - 1) * pageSize, current * pageSize),
    page: current,
    pages,
    count: kept.length,
  };
};

/** True when the list filter is empty or contains the value. */
export const matchesFilter = (selected: string[], value: string): boolean =>
  selected.length === 0 || selected.includes(value);

/** A Realtime page as the DataTable's pagination metadata. */
export const toTableMetadata = (
  page: RealtimePage<unknown>,
): MetaDataProps => ({
  pagination: { page: page.page, pages: page.pages, count: page.count },
  version: "1",
});
