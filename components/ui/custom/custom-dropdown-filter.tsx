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
import _ from "lodash";
import { useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useMemo, useState } from "react";

import { PlusCircleIcon } from "@/components/icons";
import { CustomDropdownFilterProps } from "@/types";

const filterSelectedClass =
  "inline-flex items-center border py-0.5 text-xs transition-colors border-transparent bg-default-500 text-secondary-foreground hover:bg-default-500/80 rounded-md px-2 font-normal";

export const CustomDropdownFilter: React.FC<CustomDropdownFilterProps> = ({
  filter,
  onFilterChange,
}) => {
  const searchParams = useSearchParams();
  const [groupSelected, setGroupSelected] = useState(new Set<string>());

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

  useEffect(() => {
    if (filter && getActiveFilter[filter.key]) {
      const activeValues = getActiveFilter[filter.key].split(",");
      const newSelection = new Set(activeValues);
      if (newSelection.size === allFilterKeys.length) {
        newSelection.add("all");
      }
      setGroupSelected(newSelection);
    } else {
      setGroupSelected(new Set());
    }
  }, [getActiveFilter, filter, allFilterKeys]);

  const onSelectionChange = useCallback(
    (keys: string[]) => {
      const newSelection = new Set(keys);

      if (
        newSelection.size === allFilterKeys.length &&
        !newSelection.has("all")
      ) {
        setGroupSelected(new Set(["all", ...allFilterKeys]));
      } else if (groupSelected.has("all")) {
        newSelection.delete("all");
        const remainingValues = allFilterKeys.filter((key) =>
          newSelection.has(key),
        );
        setGroupSelected(new Set(remainingValues));
      } else {
        setGroupSelected(newSelection);
      }

      if (onFilterChange && filter) {
        const selectedValues = Array.from(newSelection).filter(
          (key) => key !== "all",
        );
        onFilterChange(filter.key, selectedValues);
      }
    },
    [allFilterKeys, groupSelected, onFilterChange, filter],
  );

  const handleSelectAllClick = useCallback(() => {
    if (groupSelected.has("all")) {
      setGroupSelected(new Set());
    } else {
      setGroupSelected(new Set(["all", ...allFilterKeys]));
    }
  }, [groupSelected, allFilterKeys]);
  return (
    <div className="flex flex-col w-full gap-2">
      <Popover backdrop="transparent" placement="bottom-start">
        <PopoverTrigger>
          <Button
            className="inline-flex items-center justify-center whitespace-nowrap font-medium transition-colors focus-visible:outline-none disabled:opacity-50 border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground rounded-md px-3 text-xs h-8 border-dashed"
            startContent={<PlusCircleIcon size={16} />}
            size="sm"
          >
            <h3 className="text-small">{filter?.labelCheckboxGroup}</h3>

            {groupSelected.size > 0 && (
              <>
                <Divider orientation="vertical" className="mx-2 h-4" />

                <div className="hidden space-x-1 lg:flex max-w-24 overflow-x-auto no-scrollbar">
                  {groupSelected.size > 3 ? (
                    <span
                      className={filterSelectedClass}
                    >{`+${groupSelected.size - 2} selected`}</span>
                  ) : (
                    Array.from(groupSelected)
                      .filter((value) => value !== "all")
                      .map((value) => (
                        <div key={value} className={filterSelectedClass}>
                          {_.capitalize(value)}
                        </div>
                      ))
                  )}
                </div>
              </>
            )}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-80">
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
                onValueChange={handleSelectAllClick}
              >
                Select All
              </Checkbox>
              <Divider orientation="horizontal" className="mt-2" />
              <ScrollShadow
                hideScrollBar
                className="flex flex-col gap-y-2 py-2 max-w-56 max-h-96"
              >
                {allFilterKeys.map((value) => (
                  <Checkbox className="font-normal" key={value} value={value}>
                    {_.capitalize(value)}
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
