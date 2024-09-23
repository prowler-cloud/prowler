"use client";

import { Button } from "@nextui-org/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo } from "react";

interface DataTableFilterCustomProps {
  filters: { key: string; values: string[] }[];
}

export function DataTableFilterCustom({ filters }: DataTableFilterCustomProps) {
  const router = useRouter();
  const searchParams = useSearchParams();

  const activeFilters = useMemo(() => {
    const currentFilters: Record<string, string> = {};
    Array.from(searchParams.entries()).forEach(([key, value]) => {
      if (key.startsWith("filter[") && key.endsWith("]")) {
        const filterKey = key.slice(7, -1);
        if (filters.some((filter) => filter.key === filterKey)) {
          // eslint-disable-next-line security/detect-object-injection
          currentFilters[filterKey] = value;
        }
      }
    });
    return currentFilters;
  }, [searchParams, filters]);

  const applyFilter = useCallback(
    (key: string, value: string) => {
      const params = new URLSearchParams(searchParams);
      const filterKey = `filter[${key}]`;

      if (params.get(filterKey) === value) {
        params.delete(filterKey);
      } else {
        params.set(filterKey, value);
      }

      router.push(`?${params.toString()}`);
    },
    [router, searchParams],
  );

  return (
    <div className="flex flex-wrap items-center space-x-2">
      {filters.flatMap(({ key, values }) =>
        values.map((value) => (
          <Button
            key={`${key}-${value}`}
            onClick={() => applyFilter(key, value)}
            // eslint-disable-next-line security/detect-object-injection
            variant={activeFilters[key] === value ? "faded" : "light"}
            size="sm"
          >
            {value || "All"}
          </Button>
        )),
      )}
    </div>
  );
}
