import { Input } from "@nextui-org/react";
import debounce from "lodash.debounce";
import { SearchIcon, XCircle } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useState } from "react";

export const CustomSearchInput: React.FC = () => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [searchQuery, setSearchQuery] = useState("");

  const applySearch = useCallback(
    (query: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (query) {
        params.set("filter[search]", query);
      } else {
        params.delete("filter[search]");
      }
      router.push(`?${params.toString()}`, { scroll: false });
    },
    [router, searchParams],
  );

  const debouncedChangeHandler = useCallback(debounce(applySearch, 300), []);

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
