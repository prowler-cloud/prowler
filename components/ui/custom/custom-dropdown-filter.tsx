"use client";
const _ = require("lodash");
import {
  Badge,
  Button,
  Checkbox,
  CheckboxGroup,
  Divider,
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@nextui-org/react";
import { useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useMemo, useState } from "react";

import { PlusCircleIcon } from "@/components/icons";
import { CustomDropdownFilterProps } from "@/types";

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
    <div className="flex w-full max-w-xs flex-col gap-2">
      <Popover backdrop="opaque" placement="bottom">
        <PopoverTrigger>
          <Button
            className="bg-default-100 text-default-800"
            startContent={
              <PlusCircleIcon className="text-default-400" width={16} />
            }
            size="sm"
          >
            <h3 className="text-small">{filter?.labelCheckboxGroup}</h3>

            {groupSelected.size > 0 && (
              <>
                <Divider orientation="vertical" className="mx-2 h-4" />
                <Badge
                  variant="flat"
                  className="rounded-sm px-1 font-normal lg:hidden"
                >
                  {groupSelected.size}
                </Badge>
                <div className="hidden space-x-1 lg:flex">
                  {groupSelected.size > 2 ? (
                    <Badge
                      variant="flat"
                      className="rounded-sm px-1 font-normal"
                    >
                      {groupSelected.size} selected
                    </Badge>
                  ) : (
                    Array.from(groupSelected)
                      .filter((value) => value !== "all")
                      .map((value) => (
                        <Badge
                          variant="flat"
                          key={value}
                          className="rounded-sm px-1 font-normal"
                        >
                          {value}
                        </Badge>
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
              className="text-small font-bold"
            >
              <Checkbox
                className="font-normal"
                value="all"
                onValueChange={handleSelectAllClick}
              >
                Select All
              </Checkbox>
              {allFilterKeys.map((value) => (
                <Checkbox className="font-normal" key={value} value={value}>
                  {_.capitalize(value)}
                </Checkbox>
              ))}
            </CheckboxGroup>
          </div>
        </PopoverContent>
      </Popover>
      {groupSelected?.size > 0 && (
        <p className="text-small text-default-500">
          Selected:{" "}
          {Array.from(groupSelected)
            .filter((item) => item !== "all")
            .join(", ")}
        </p>
      )}
    </div>
  );
};
