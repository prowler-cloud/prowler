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
      style={{
        borderRadius: "0.5rem",
      }}
      classNames={{
        base: "w-full [&]:!rounded-lg [&>*]:!rounded-lg",
        input:
          "text-bg-button-secondary placeholder:text-bg-button-secondary text-sm",
        inputWrapper:
          "!border-border-input-primary !bg-bg-input-primary dark:!bg-input/30 dark:hover:!bg-input/50 hover:!bg-bg-neutral-secondary !border [&]:!rounded-lg !shadow-xs !transition-[color,box-shadow] focus-within:!border-border-input-primary-press focus-within:!ring-1 focus-within:!ring-border-input-primary-press focus-within:!ring-offset-1 !h-10 !px-4 !py-3 !outline-none",
        clearButton: "text-bg-button-secondary",
      }}
      aria-label="Search"
      placeholder="Search..."
      value={searchQuery}
      startContent={
        <SearchIcon className="text-bg-button-secondary shrink-0" width={16} />
      }
      onChange={(e) => {
        const value = e.target.value;
        setSearchQuery(value);
        debouncedChangeHandler(value);
      }}
      endContent={
        searchQuery && (
          <button
            onClick={clearIconSearch}
            className="text-bg-button-secondary shrink-0 focus:outline-none"
          >
            <XCircle className="text-bg-button-secondary h-4 w-4" />
          </button>
        )
      }
    />
  );
};
