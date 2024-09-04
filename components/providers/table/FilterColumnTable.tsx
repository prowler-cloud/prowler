import { Button, Input } from "@nextui-org/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";

import { useDebounce } from "@/hooks/useDebounce";

interface FilterColumnTableProps {
  filters: { key: string; values: string[] }[];
}

export function FilterColumnTable({ filters }: FilterColumnTableProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [searchQuery, setSearchQuery] = useState("");
  const debouncedSearchQuery = useDebounce(searchQuery, 300);

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
        // If the filter is already set, remove it
        params.delete(filterKey);
      } else {
        // Otherwise, set or update the filter
        params.set(filterKey, value);
      }

      router.push(`?${params.toString()}`);
    },
    [router, searchParams],
  );

  const applySearch = useCallback(
    (query: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (query) {
        params.set("filter[search]", query);
      } else {
        params.delete("filter[search]");
      }
      console.log(params.toString(), "en el apply search");
      router.push(`?${params.toString()}`, { scroll: false });
    },
    [router, searchParams],
  );

  useEffect(() => {
    applySearch(debouncedSearchQuery);
  }, [debouncedSearchQuery, applySearch]);

  return (
    <div className="flex flex-col md:flex-row justify-between space-y-4 w-full items-center">
      <div className="w-full md:w-1/3">
        <Input
          placeholder="Search..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              applySearch(searchQuery);
            }
          }}
        />
      </div>
      <div className="flex items-center space-x-2">
        {filters.flatMap(({ key, values }) =>
          values.map((value) => (
            <Button
              key={`${key}-${value}`}
              onClick={() => applyFilter(key, value)}
              // eslint-disable-next-line security/detect-object-injection
              variant={activeFilters[key] === value ? "faded" : "light"}
            >
              {value || "All"}
            </Button>
          )),
        )}
      </div>
    </div>
  );
}
