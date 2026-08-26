import { COMPLIANCE_TAB } from "@/types/compliance";

export function buildPerScanComplianceHref(
  params?: Record<string, string>,
): string {
  const extras = new URLSearchParams(params);
  extras.delete("tab");

  const search = new URLSearchParams({ tab: COMPLIANCE_TAB.PER_SCAN });
  extras.forEach((value, key) => search.append(key, value));

  return `/compliance?${search.toString()}`;
}

export function buildMultipleScansComplianceHref(): string {
  return "/compliance";
}
