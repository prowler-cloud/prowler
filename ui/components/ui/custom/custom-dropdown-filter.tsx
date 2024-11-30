"use client";

import {
  Button,
  Checkbox,
  CheckboxGroup,
  Divider,
  Popover,
  PopoverContent,
  PopoverTrigger,
  ScrollShadow,
} from "@nextui-org/react";
import { XCircle } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useMemo, useState } from "react";

import { PlusCircleIcon } from "@/components/icons";
import { CustomDropdownFilterProps } from "@/types";

const filterSelectedClass =
  "inline-flex items-center border py-1 text-xs transition-colors border-transparent bg-default-500 text-secondary-foreground hover:bg-default-500/80 rounded-md px-2 font-normal";

export const CustomDropdownFilter: React.FC<CustomDropdownFilterProps> = ({
  filter,
  onFilterChange,
}) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [groupSelected, setGroupSelected] = useState(new Set<string>());
  const [pendingClearFilter, setPendingClearFilter] = useState<string | null>(
    null,
  );

  const allFilterKeys = filter?.values || [];

  const getActiveFilter = useMemo(() => {
    const currentFilters: Record<string, string> = {};
    Array.from(searchParams.entries()).forEach(([key, value]) => {
      if (key.startsWith("filter[") && key.endsWith("]")) {
        const filterKey = key.slice(7, -1);
        if (filter && filter.key === filterKey) {
          // eslint-disable-next-line security/detect-object-injection
          currentFilters[filterKey] = value;
        }
      }
    });
    return currentFilters;
  }, [searchParams, filter]);

  const memoizedFilterValues = useMemo(
    () => filter?.values || [],
    [filter?.values],
  );

  useEffect(() => {
    if (filter && getActiveFilter[filter.key]) {
      const activeValues = getActiveFilter[filter.key].split(",");
      const newSelection = new Set(activeValues);
      if (newSelection.size === memoizedFilterValues.length) {
        newSelection.add("all");
      }
      setGroupSelected(newSelection);
    } else {
      setGroupSelected(new Set());
    }
  }, [getActiveFilter, filter?.key, memoizedFilterValues]);

  const onSelectionChange = useCallback(
    (keys: string[]) => {
      setGroupSelected((prevGroupSelected) => {
        const newSelection = new Set(keys);

        if (
          newSelection.size === allFilterKeys.length &&
          !newSelection.has("all")
        ) {
          return new Set(["all", ...allFilterKeys]);
        } else if (prevGroupSelected.has("all")) {
          newSelection.delete("all");
          return new Set(allFilterKeys.filter((key) => newSelection.has(key)));
        }
        return newSelection;
      });

      if (onFilterChange && filter) {
        const selectedValues = keys.filter((key) => key !== "all");
        onFilterChange(filter.key, selectedValues);
      }
    },
    [allFilterKeys, onFilterChange, filter],
  );

  const handleSelectAllClick = useCallback(() => {
    setGroupSelected((prevGroupSelected: Set<string>) => {
      const newSelection: Set<string> = prevGroupSelected.has("all")
        ? new Set()
        : new Set(["all", ...allFilterKeys]);

      if (onFilterChange && filter) {
        const selectedValues = Array.from(newSelection).filter(
          (key) => key !== "all",
        );
        onFilterChange(filter.key, selectedValues);
      }

      return newSelection;
    });
  }, [allFilterKeys, onFilterChange, filter]);

  // Update the pending clear filter
  const onClearFilter = useCallback((filterKey: string) => {
    setPendingClearFilter(filterKey);
  }, []);

  // Execute the update in the router after the render
  useEffect(() => {
    if (pendingClearFilter) {
      const params = new URLSearchParams(searchParams.toString());
      params.delete(`filter[${pendingClearFilter}]`);
      router.push(`?${params.toString()}`, { scroll: false });
      setPendingClearFilter(null); // Reset the state
    }
  }, [pendingClearFilter, searchParams, router]);

  return (
    <div className="relative flex w-full flex-col gap-2">
      <Button
        isIconOnly
        variant="light"
        onClick={(e) => {
          e.stopPropagation();
          onClearFilter(filter.key);
        }}
        className={`absolute right-2 top-1/2 z-40 -translate-y-1/2 ${
          groupSelected.size === 0 ? "hidden" : ""
        }`}
      >
        <XCircle className="h-4 w-4 text-default-400" />
      </Button>
      <Popover backdrop="transparent" placement="bottom-start">
        <PopoverTrigger>
          <Button
            className="border-input hover:bg-accent hover:text-accent-foreground inline-flex h-10 items-center justify-center whitespace-nowrap rounded-md border border-dashed bg-background px-3 text-xs font-medium shadow-sm transition-colors focus-visible:outline-none disabled:opacity-50 dark:bg-prowler-blue-800"
            startContent={<PlusCircleIcon size={16} />}
            size="md"
          >
            <h3 className="text-small">{filter?.labelCheckboxGroup}</h3>

            {groupSelected.size > 0 && (
              <>
                <Divider orientation="vertical" className="mx-2 h-4" />

                <div className="flex items-center gap-2">
                  <div className="no-scrollbar hidden max-w-24 space-x-1 overflow-x-auto lg:flex">
                    {groupSelected.size > 3 ? (
                      <span className={filterSelectedClass}>
                        {`+${groupSelected.size - 2} selected`}
                      </span>
                    ) : (
                      Array.from(groupSelected)
                        .filter((value) => value !== "all")
                        .map((value) => (
                          <div key={value} className={filterSelectedClass}>
                            {value}
                          </div>
                        ))
                    )}
                  </div>
                </div>
              </>
            )}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-80 dark:bg-prowler-blue-800">
          <div className="flex w-full flex-col gap-6 p-2">
            <CheckboxGroup
              color="default"
              label={filter?.labelCheckboxGroup}
              value={Array.from(groupSelected)}
              onValueChange={onSelectionChange}
              className="font-bold"
            >
              <Checkbox
                className="font-normal"
                value="all"
                isSelected={groupSelected.has("all")}
                onClick={handleSelectAllClick}
              >
                Select All
              </Checkbox>
              <Divider orientation="horizontal" className="mt-2" />
              <ScrollShadow
                hideScrollBar
                className="flex max-h-96 max-w-56 flex-col gap-y-2 py-2"
              >
                {memoizedFilterValues.map((value) => (
                  <Checkbox className="font-normal" key={value} value={value}>
                    {value}
                  </Checkbox>
                ))}
              </ScrollShadow>
            </CheckboxGroup>
          </div>
        </PopoverContent>
      </Popover>
    </div>
  );
};
