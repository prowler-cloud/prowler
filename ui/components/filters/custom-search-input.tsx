import { Input } from "@nextui-org/react";
import debounce from "lodash.debounce";
import { SearchIcon, XCircle } from "lucide-react";
import { useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useState } from "react";

import { useUrlFilters } from "@/hooks/use-url-filters";

export const CustomSearchInput: React.FC = () => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [searchQuery, setSearchQuery] = useState("");

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
      debounce((val) => applySearch(val), 300)(value);
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

  return (
    <Input
      variant="flat"
      classNames={{
        label: "tracking-tight font-light !text-default-600 text-sm !z-0 pb-1",
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
            <XCircle className="h-4 w-4 text-default-400" />
          </button>
        )
      }
      radius="sm"
      size="sm"
    />
  );
};
