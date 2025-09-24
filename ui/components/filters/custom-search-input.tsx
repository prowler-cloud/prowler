import { Input } from "@heroui/input";

import { SearchIcon, XCircle } from "lucide-react";
import { useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useRef, useState } from "react";

import { useUrlFilters } from "@/hooks/use-url-filters";

export const CustomSearchInput: React.FC = () => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [searchQuery, setSearchQuery] = useState("");
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const applySearch = useCallback(
    (query: string) => {
      if (query) {
        updateFilter("search", query);
      } else {
        updateFilter("search", null);
      }
    },
    [updateFilter],
  );

  const debouncedChangeHandler = useCallback(
    (value: string) => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
      debounceTimeoutRef.current = setTimeout(() => {
        applySearch(value);
      }, 300);
    },
    [applySearch],
  );

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
    <Input
      variant="flat"
      classNames={{
        label: "tracking-tight font-light !text-default-600 text-sm z-0! pb-1",
      }}
      aria-label="Search"
      label="Search"
      placeholder="Search..."
      labelPlacement="inside"
      value={searchQuery}
      startContent={<SearchIcon className="text-default-400" width={16} />}
      onChange={(e) => {
        const value = e.target.value;
        setSearchQuery(value);
        debouncedChangeHandler(value);
      }}
      endContent={
        searchQuery && (
          <button onClick={clearIconSearch} className="focus:outline-none">
            <XCircle className="text-default-400 h-4 w-4" />
          </button>
        )
      }
      radius="sm"
      size="sm"
    />
  );
};
