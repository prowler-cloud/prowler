"use client";

import { Button } from "@nextui-org/react";
// import {
//   Button,
//   Input,
//   Popover,
//   PopoverContent,
//   PopoverTrigger,
//   RadioGroup,
// } from "@nextui-org/react";
// import { Icon, Radio, SearchIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo } from "react";

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
      {/* <div className="flex items-center gap-4 overflow-auto px-[6px] py-[4px]">
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
                <Button className="bg-default-100 text-default-800" size="sm">
                  Filter
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-80">
                <div className="flex w-full flex-col gap-6 px-2 py-4">
                  <RadioGroup
                    label="Worker Type"
                    // value={workerTypeFilter}
                    // onValueChange={setWorkerTypeFilter}
                  >
                    <Radio value="all">All</Radio>
                    <Radio value="employee">Employee</Radio>
                    <Radio value="contractor">Contractor</Radio>
                  </RadioGroup>

                  <RadioGroup
                    label="Status"
                    // value={statusFilter}
                    // onValueChange={setStatusFilter}
                  >
                    <Radio value="all">All</Radio>
                    <Radio value="active">Active</Radio>
                    <Radio value="inactive">Inactive</Radio>
                    <Radio value="paused">Paused</Radio>
                    <Radio value="vacation">Vacation</Radio>
                  </RadioGroup>

                  <RadioGroup
                    label="Start Date"
                    // value={startDateFilter}
                    // onValueChange={setStartDateFilter}
                  >
                    <Radio value="all">All</Radio>
                    <Radio value="last7Days">Last 7 days</Radio>
                    <Radio value="last30Days">Last 30 days</Radio>
                    <Radio value="last60Days">Last 60 days</Radio>
                  </RadioGroup>
                </div>
              </PopoverContent>
            </Popover>
          </div>
        </div>
      </div> */}

      <div className="flex flex-wrap items-center space-x-2">
        {filters.flatMap(({ key, values }) =>
          values.map((value) => (
            <Button
              key={`${key}-${value}`}
              onClick={() => applyFilter(key, value)}
              // eslint-disable-next-line security/detect-object-injection
              variant={activeFilters[key] === value ? "faded" : "light"}
              size="sm"
            >
              {value || "All"}
            </Button>
          )),
        )}
      </div>
    </>
  );
}
