import { COMPLIANCE_TAB } from "@/types/compliance";

/**
 * Builds a `/compliance` URL pinned to the Single Scan tab.
 *
 * Multiple Scans is the default landing tab and owns the bare `/compliance`
 * route, so every link that targets one concrete scan has to pin Single Scan
 * explicitly or it lands on the aggregated view instead.
 */
export function buildPerScanComplianceHref(
  params?: Record<string, string>,
): string {
  // `tab` is owned by this helper: a caller-supplied one would silently defeat
  // the pin the function name promises, so it is dropped rather than merged.
  const extras = new URLSearchParams(params);
  extras.delete("tab");

  const search = new URLSearchParams({ tab: COMPLIANCE_TAB.PER_SCAN });
  extras.forEach((value, key) => search.append(key, value));

  return `/compliance?${search.toString()}`;
}
