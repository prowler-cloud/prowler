import { Input } from "@nextui-org/react";
import { XCircle } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useState } from "react";

import { useDebounce } from "../../hooks/useDebounce";

export const CustomSearchInput: React.FC = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [searchQuery, setSearchQuery] = useState(() => {
    return searchParams.get("filter[search]") || "";
  });
  const debouncedSearchQuery = useDebounce(searchQuery, 500);

  const applySearch = useCallback(
    (query: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (query) {
        params.set("filter[search]", query);
      } else {
        params.delete("filter[search]");
      }
      router.replace(`?${params.toString()}`, { scroll: false });
    },
    [router, searchParams],
  );

  const clearIconSearch = () => {
    setSearchQuery("");
    applySearch("");
  };

  useEffect(() => {
    applySearch(debouncedSearchQuery);
  }, [debouncedSearchQuery, applySearch]);

  return (
    <Input
      variant="bordered"
      placeholder="Search..."
      label="Search"
      labelPlacement="inside"
      value={searchQuery}
      onChange={(e) => setSearchQuery(e.target.value)}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          applySearch(searchQuery);
        }
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
