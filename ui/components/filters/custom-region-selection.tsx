"use client";

import { Select, SelectItem } from "@nextui-org/react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useMemo } from "react";

import { regions } from "@/lib/helper";

export const CustomRegionSelection: React.FC = () => {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Memoize selected keys based on the URL
  const selectedKeys = useMemo(() => {
    const params = searchParams.get("filter[regions]");
    return params ? params.split(",") : [];
  }, [searchParams]);

  const applyRegionFilter = useCallback(
    (values: string[]) => {
      const params = new URLSearchParams(searchParams.toString());
      if (values.length > 0) {
        params.set("filter[regions]", values.join(","));
      } else {
        params.delete("filter[regions]");
      }
      router.push(`?${params.toString()}`, { scroll: false });
    },
    [router, searchParams],
  );

  return (
    <Select
      label="Region"
      aria-label="Select a Region"
      placeholder="Select a region"
      selectionMode="multiple"
      className="w-full"
      size="sm"
      selectedKeys={selectedKeys}
      onSelectionChange={(keys) => applyRegionFilter(Array.from(keys))}
    >
      {regions.map((region) => (
        <SelectItem key={region.key}>{region.label}</SelectItem>
      ))}
    </Select>
  );
};
