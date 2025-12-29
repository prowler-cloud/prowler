"use client";

import { LoaderCircleIcon, SearchIcon } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";

import { Input } from "@/components/shadcn/input/input";
import { useUrlFilters } from "@/hooks/use-url-filters";

export const DataTableSearch = () => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [value, setValue] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const id = useId();
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Sync with URL on mount
  useEffect(() => {
    const searchFromUrl = searchParams.get("filter[search]") || "";
    setValue(searchFromUrl);
  }, [searchParams]);

  // Handle input change with debounce
  const handleChange = (newValue: string) => {
    setValue(newValue);

    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }

    if (newValue) {
      setIsLoading(true);
      debounceTimeoutRef.current = setTimeout(() => {
        updateFilter("search", newValue);
        setIsLoading(false);
      }, 300);
    } else {
      setIsLoading(false);
      updateFilter("search", null);
    }
  };

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current);
      }
    };
  }, []);

  return (
    <div className="relative w-64">
      <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
        <SearchIcon className="text-text-neutral-tertiary size-4" />
      </div>
      <Input
        id={id}
        type="search"
        placeholder="Search..."
        value={value}
        onChange={(e) => handleChange(e.target.value)}
        className="border-border-neutral-tertiary bg-bg-neutral-tertiary pr-9 pl-9 [&::-webkit-search-cancel-button]:appearance-none [&::-webkit-search-decoration]:appearance-none [&::-webkit-search-results-button]:appearance-none [&::-webkit-search-results-decoration]:appearance-none"
      />
      {isLoading && (
        <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
          <LoaderCircleIcon className="text-text-neutral-tertiary size-4 animate-spin" />
        </div>
      )}
    </div>
  );
};
