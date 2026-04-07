"use client";

import { X } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { filterScans } from "@/components/filters/data-filters";
import { FilterControls } from "@/components/filters/filter-controls";
import { Badge } from "@/components/shadcn/badge/badge";
import { useRelatedFilters } from "@/hooks";
import { FilterEntity, FilterType } from "@/types";

interface ScansFiltersProps {
  providerUIDs: string[];
  providerDetails: { [uid: string]: FilterEntity }[];
}

export const ScansFilters = ({
  providerUIDs,
  providerDetails,
}: ScansFiltersProps) => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const idFilter = searchParams.get("filter[id__in]");

  const { availableProviderUIDs } = useRelatedFilters({
    providerUIDs,
    providerDetails,
    enableScanRelation: false,
    providerFilterType: FilterType.PROVIDER_UID,
  });

  const handleDismissIdFilter = () => {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("filter[id__in]");
    router.push(`${pathname}?${params.toString()}`);
  };

  const scanIdChip = idFilter ? (
    <div className="flex items-center">
      <Badge
        variant="tag"
        className="max-w-[300px] shrink-0 cursor-default gap-1 truncate"
      >
        <span className="text-text-neutral-secondary mr-1 text-xs">Scan:</span>
        <span className="truncate">{idFilter}</span>
        <button
          type="button"
          aria-label="Clear scan filter"
          className="hover:text-text-neutral-primary ml-0.5 shrink-0"
          onClick={handleDismissIdFilter}
        >
          <X className="size-3" />
        </button>
      </Badge>
    </div>
  ) : null;

  return (
    <FilterControls
      customFilters={[
        ...filterScans,
        {
          key: FilterType.PROVIDER_UID,
          labelCheckboxGroup: "Provider UID",
          values: availableProviderUIDs,
          valueLabelMapping: providerDetails,
          index: 1,
        },
      ]}
      prependElement={scanIdChip}
    />
  );
};
