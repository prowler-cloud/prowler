"use client";

import {
  Button,
  Checkbox,
  CheckboxGroup,
  Input,
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@nextui-org/react";
import { SearchIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo } from "react";

import { CustomFilterIcon, PlusCircleIcon } from "@/components/icons";
import { CustomButton } from "@/components/ui/custom";

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
    <>
      <div className="flex items-center gap-4 overflow-auto px-[6px] py-[4px]">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-4">
            <Input
              className="min-w-[200px]"
              endContent={
                <SearchIcon className="text-default-400" width={16} />
              }
              placeholder="Search"
              size="sm"
              // value={filterValue}
              // onValueChange={onSearchChange}
            />
          </div>
          <div>
            <Popover placement="bottom">
              <PopoverTrigger>
                <Button
                  className="bg-default-100 text-default-800"
                  startContent={
                    <PlusCircleIcon className="text-default-400" width={16} />
                  }
                  size="sm"
                >
                  Filter
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-80">
                <div className="flex w-full flex-col gap-6 px-2 py-4">
                  <CheckboxGroup
                    label="Select cities"
                    defaultValue={["buenos-aires", "london"]}
                  >
                    <Checkbox value="buenos-aires">Buenos Aires</Checkbox>
                    <Checkbox value="sydney">Sydney</Checkbox>
                    <Checkbox value="san-francisco">San Francisco</Checkbox>
                    <Checkbox value="london">London</Checkbox>
                    <Checkbox value="tokyo">Tokyo</Checkbox>
                  </CheckboxGroup>
                </div>
              </PopoverContent>
            </Popover>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center space-x-2">
        <CustomButton
          variant="dashed"
          size="sm"
          startContent={<CustomFilterIcon size={16} />}
        >
          Show Filters
        </CustomButton>
        {filters.flatMap(({ key, values }) =>
          values.map((value) => (
            <Button
              key={`${key}-${value}`}
              onPress={() => applyFilter(key, value)}
              // eslint-disable-next-line security/detect-object-injection
              variant={activeFilters[key] === value ? "faded" : "light"}
            >
              {value || "All"}
            </Button>
          )),
        )}
      </div>
    </>
  );
}
