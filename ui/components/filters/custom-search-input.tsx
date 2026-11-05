import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { SearchInput } from "@/components/shadcn";
import { useUrlFilters } from "@/hooks/use-url-filters";

export const CustomSearchInput = () => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [searchQuery, setSearchQuery] = useState("");
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const applySearch = (query: string) => {
    if (query) {
      updateFilter("search", query);
    } else {
      updateFilter("search", null);
    }
  };

  const debouncedChangeHandler = (value: string) => {
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }
    debounceTimeoutRef.current = setTimeout(() => {
      applySearch(value);
    }, 300);
  };

  const clearIconSearch = () => {
    setSearchQuery("");
    applySearch("");
  };

  useEffect(() => {
    const searchFromUrl = searchParams.get("filter[search]") || "";
    setSearchQuery(searchFromUrl);
  }, [searchParams]);

  useEffect(() => {
    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
    };
  }, []);

  return (
    <SearchInput
      aria-label="Search"
      placeholder="Search..."
      value={searchQuery}
      onChange={(e) => {
        const value = e.target.value;
        setSearchQuery(value);
        debouncedChangeHandler(value);
      }}
      onClear={clearIconSearch}
    />
  );
};
