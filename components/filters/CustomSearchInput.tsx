import { Input } from "@nextui-org/react";
import { XCircle } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useState } from "react";

import { useDebounce } from "../../hooks/useDebounce";

export const CustomSearchInput: React.FC = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  // const [searchQuery, setSearchQuery] = useState(() => {
  //   return searchParams.get("filter[search]") || "";
  // });
  const [searchQuery, setSearchQuery] = useState("");

  const debouncedSearchQuery = useDebounce(searchQuery, 500);
  console.log("debouncedSearchQuery", debouncedSearchQuery);

  const applySearch = useCallback(
    (query: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (query) {
        params.set("filter[search]", query);
        setSearchQuery(query);
      } else {
        params.delete("filter[search]");
      }
      router.push(`?${params.toString()}`, { scroll: false });
    },
    [router, searchParams],
  );

  const clearIconSearch = () => {
    setSearchQuery("");
    applySearch("");
  };

  useEffect(() => {
    const searchFromUrl = searchParams.get("filter[search]") || "";
    setSearchQuery(searchFromUrl);
  }, [searchParams]);

  // useEffect(() => {
  //   const timer = setTimeout(() => {
  //     applySearch(debouncedSearchQuery);
  //     console.log("hi from useEffect");
  //   }, 2000);

  //   return () => clearTimeout(timer);
  // }, [debouncedSearchQuery, applySearch, searchParams]);

  return (
    <Input
      variant="bordered"
      placeholder="Search..."
      label="Search"
      labelPlacement="inside"
      value={searchQuery}
      onChange={(e) => {
        const value = e.target.value;
        setSearchQuery(value);
        applySearch(value);
      }}
      endContent={
        searchQuery && (
          <button onClick={clearIconSearch} className="focus:outline-none">
            <XCircle className="h-4 w-4 text-default-400" />
          </button>
        )
      }
      size="sm"
    />
  );
};
