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
import { ChevronDown, X } from "lucide-react";
import { useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useMemo, useState } from "react";

import { CustomDropdownFilterProps } from "@/types";

import { EntityInfoShort } from "../entities";

export const CustomDropdownFilter: React.FC<CustomDropdownFilterProps> = ({
  filter,
  onFilterChange,
}) => {
  const searchParams = useSearchParams();
  const [groupSelected, setGroupSelected] = useState(new Set<string>());
  const [isOpen, setIsOpen] = useState(false);

  // Simplified: combine filter values and selected values logic
  const filterValues = useMemo(() => filter?.values || [], [filter?.values]);
  const selectedValues = Array.from(groupSelected).filter(
    (value) => value !== "all",
  );
  const isAllSelected =
    selectedValues.length === filterValues.length && filterValues.length > 0;

  // Simplified: direct URL parsing without extra memoization
  const activeFilterValue = useMemo(() => {
    const filterParam = searchParams.get(`filter[${filter?.key}]`);
    return filterParam ? filterParam.split(",") : [];
  }, [searchParams, filter?.key]);

  // Sync URL state with component state
  useEffect(() => {
    if (activeFilterValue.length > 0) {
      const newSelection = new Set(activeFilterValue);
      if (newSelection.size === filterValues.length) {
        newSelection.add("all");
      }
      setGroupSelected(newSelection);
    } else {
      setGroupSelected(new Set());
    }
  }, [activeFilterValue, filterValues.length]);

  // Simplified: single function to handle all selection changes
  const updateSelection = useCallback(
    (newValues: string[]) => {
      const newSelection = new Set(newValues);

      // Auto-add "all" if all items are selected
      if (
        newSelection.size === filterValues.length &&
        !newSelection.has("all")
      ) {
        newSelection.add("all");
      }

      setGroupSelected(newSelection);

      // Notify parent with actual values (excluding "all")
      const actualValues = newValues.filter((key) => key !== "all");
      onFilterChange?.(filter.key, actualValues);
    },
    [filterValues.length, onFilterChange, filter.key],
  );

  const onSelectionChange = useCallback(
    (keys: string[]) => {
      // Handle "all" selection logic
      if (keys.includes("all")) {
        if (groupSelected.has("all")) {
          updateSelection([]);
        } else {
          updateSelection(filterValues);
        }
      } else {
        updateSelection(keys);
      }
    },
    [groupSelected, updateSelection, filterValues],
  );

  const handleSelectAllClick = useCallback(() => {
    const newValues = groupSelected.has("all") ? [] : filterValues;
    updateSelection(newValues);
  }, [groupSelected, updateSelection, filterValues]);

  const handleClearAll = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      updateSelection([]);
    },
    [updateSelection],
  );

  // Simplified: inline display label logic
  const getDisplayLabel = useCallback(
    (value: string) => {
      const entity = filter.valueLabelMapping?.find((entry) => entry[value])?.[
        value
      ];
      return entity?.alias || entity?.uid || value;
    },
    [filter.valueLabelMapping],
  );

  return (
    <div className="flex w-full flex-col gap-2">
      <Popover
        backdrop="transparent"
        placement="bottom-start"
        isOpen={isOpen}
        onOpenChange={setIsOpen}
      >
        <PopoverTrigger>
          <Button
            className="border-input hover:bg-accent hover:text-accent-foreground inline-flex h-auto min-h-10 items-center justify-between whitespace-nowrap rounded-md border border-dashed bg-background px-3 py-2 text-xs font-medium shadow-sm transition-colors focus-visible:outline-none disabled:opacity-50 dark:bg-prowler-blue-800"
            endContent={
              <ChevronDown
                className={`h-4 w-4 transition-transform ${isOpen ? "rotate-180" : ""}`}
              />
            }
            size="md"
            variant="flat"
          >
            <div className="flex min-w-0 flex-1 items-center gap-2">
              <span className="flex-shrink-0 text-small">
                {filter?.labelCheckboxGroup}
              </span>

              {selectedValues.length > 0 && (
                <>
                  <Divider
                    orientation="vertical"
                    className="h-4 flex-shrink-0"
                  />
                  <div className="flex min-w-0 flex-shrink items-center">
                    {selectedValues.length <= 2 ? (
                      <span
                        className="max-w-32 truncate text-xs text-default-500"
                        title={selectedValues.map(getDisplayLabel).join(", ")}
                      >
                        {selectedValues.map(getDisplayLabel).join(", ")}
                      </span>
                    ) : (
                      <span className="truncate text-xs text-default-500">
                        {isAllSelected
                          ? "All selected"
                          : `${selectedValues.length} selected`}
                      </span>
                    )}
                    <button
                      onClick={handleClearAll}
                      className="ml-1 flex h-4 w-4 flex-shrink-0 items-center justify-center rounded-full transition-colors hover:bg-default-200"
                      aria-label="Clear selection"
                    >
                      <X className="h-3 w-3 text-default-400 hover:text-default-600" />
                    </button>
                  </div>
                </>
              )}
            </div>
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-80 dark:bg-prowler-blue-800">
          <div className="flex w-full flex-col gap-4 p-2">
            <CheckboxGroup
              color="default"
              label={filter?.labelCheckboxGroup}
              value={Array.from(groupSelected)}
              onValueChange={onSelectionChange}
              className="font-bold"
            >
              <Checkbox
                classNames={{
                  label: "text-small font-normal",
                  wrapper: "checkbox-update",
                }}
                value="all"
                isSelected={groupSelected.has("all")}
                onClick={handleSelectAllClick}
              >
                Select All
              </Checkbox>
              <Divider orientation="horizontal" className="mt-2" />
              <ScrollShadow
                hideScrollBar
                className="flex max-h-96 max-w-full flex-col gap-y-2 py-2"
              >
                {filterValues.map((value) => {
                  const entity = filter.valueLabelMapping?.find(
                    (entry) => entry[value],
                  )?.[value];

                  return (
                    <Checkbox
                      classNames={{
                        label: "text-small font-normal",
                        wrapper: "checkbox-update",
                      }}
                      key={value}
                      value={value}
                    >
                      {entity ? (
                        <EntityInfoShort
                          cloudProvider={entity.provider}
                          entityAlias={entity.alias ?? undefined}
                          entityId={entity.uid}
                          hideCopyButton
                        />
                      ) : (
                        value
                      )}
                    </Checkbox>
                  );
                })}
              </ScrollShadow>
            </CheckboxGroup>
          </div>
        </PopoverContent>
      </Popover>
    </div>
  );
};
