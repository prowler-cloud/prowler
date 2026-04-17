import { formatLabel, getCategoryLabel, getGroupLabel } from "@/lib/categories";
import { FINDING_STATUS_DISPLAY_NAMES } from "@/types";
import { getProviderDisplayName, ProviderProps } from "@/types/providers";
import { ScanEntity } from "@/types/scans";
import { SEVERITY_DISPLAY_NAMES } from "@/types/severities";

interface GetFindingsFilterDisplayValueOptions {
  providers?: ProviderProps[];
  scans?: Array<{ [scanId: string]: ScanEntity }>;
}

const FINDING_DELTA_DISPLAY_NAMES: Record<string, string> = {
  new: "New",
  changed: "Changed",
};

function getProviderAccountDisplayValue(
  providerId: string,
  providers: ProviderProps[],
): string {
  const provider = providers.find((item) => item.id === providerId);
  if (!provider) {
    return providerId;
  }

  return provider.attributes.alias || provider.attributes.uid || providerId;
}

function getScanDisplayValue(
  scanId: string,
  scans: Array<{ [scanId: string]: ScanEntity }>,
): string {
  const scan = scans.find((item) => item[scanId])?.[scanId];
  if (!scan) {
    return scanId;
  }

  return (
    scan.attributes.name ||
    scan.providerInfo.alias ||
    scan.providerInfo.uid ||
    scanId
  );
}

export function getFindingsFilterDisplayValue(
  filterKey: string,
  value: string,
  options: GetFindingsFilterDisplayValueOptions = {},
): string {
  if (!value) return value;
  if (filterKey === "filter[provider_type__in]") {
    return getProviderDisplayName(value);
  }
  if (filterKey === "filter[provider_id__in]") {
    return getProviderAccountDisplayValue(value, options.providers || []);
  }
  if (filterKey === "filter[scan__in]") {
    return getScanDisplayValue(value, options.scans || []);
  }
  if (filterKey === "filter[severity__in]") {
    return (
      SEVERITY_DISPLAY_NAMES[
        value.toLowerCase() as keyof typeof SEVERITY_DISPLAY_NAMES
      ] ?? formatLabel(value)
    );
  }
  if (filterKey === "filter[status__in]") {
    return (
      FINDING_STATUS_DISPLAY_NAMES[
        value as keyof typeof FINDING_STATUS_DISPLAY_NAMES
      ] ?? formatLabel(value)
    );
  }
  if (filterKey === "filter[delta__in]") {
    return (
      FINDING_DELTA_DISPLAY_NAMES[value.toLowerCase()] ?? formatLabel(value)
    );
  }
  if (filterKey === "filter[category__in]") {
    return getCategoryLabel(value);
  }
  if (filterKey === "filter[resource_groups__in]") {
    return getGroupLabel(value);
  }
  if (
    filterKey === "filter[inserted_at]" ||
    filterKey === "filter[inserted_at__gte]" ||
    filterKey === "filter[inserted_at__lte]"
  ) {
    return value;
  }

  return formatLabel(value);
}
