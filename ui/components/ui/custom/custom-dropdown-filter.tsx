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
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { ComplianceScanInfo } from "@/components/compliance/compliance-header/compliance-scan-info";
import { EntityInfoShort } from "@/components/ui/entities";
import { isScanEntity } from "@/lib/helper-filters";
import {
  CustomDropdownFilterProps,
  FilterEntity,
  ProviderEntity,
  ScanEntity,
} from "@/types";

export const CustomDropdownFilter = ({
  filter,
  onFilterChange,
}: CustomDropdownFilterProps) => {
  const searchParams = useSearchParams();
  const [groupSelected, setGroupSelected] = useState(new Set<string>());
  const [isOpen, setIsOpen] = useState(false);
  const hasUserInteracted = useRef(false);

  const filterValues = useMemo(() => filter?.values || [], [filter?.values]);
  const selectedValues = Array.from(groupSelected).filter(
    (value) => value !== "all",
  );
  const isAllSelected =
    selectedValues.length === filterValues.length && filterValues.length > 0;

  const activeFilterValue = useMemo(() => {
    const filterParam = searchParams.get(`filter[${filter?.key}]`);
    return filterParam ? filterParam.split(",") : [];
  }, [searchParams, filter?.key]);

  // Helper function to handle URL filter values sync
  const syncWithActiveFilters = useCallback(() => {
    const newSelection = new Set(activeFilterValue);
    if (
      newSelection.size === filterValues.length &&
      filter?.showSelectAll !== false
    ) {
      newSelection.add("all");
    }
    setGroupSelected(newSelection);
  }, [activeFilterValue, filterValues, filter?.showSelectAll]);

  const resetComponentState = useCallback(() => {
    setGroupSelected(new Set());
    hasUserInteracted.current = false;
  }, []);

  const applyDefaultValues = useCallback(() => {
    if (filter?.defaultToSelectAll && filterValues.length > 0) {
      const newSelection = new Set(filterValues);
      if (filter?.showSelectAll !== false) {
        newSelection.add("all");
      }
      setGroupSelected(newSelection);
    } else if (filter?.defaultValues && filter.defaultValues.length > 0) {
      const validDefaultValues = filter.defaultValues.filter((value) =>
        filterValues.includes(value),
      );
      const newSelection = new Set(validDefaultValues);

      // Add "all" if all items are selected and showSelectAll is not false
      if (
        validDefaultValues.length === filterValues.length &&
        filter?.showSelectAll !== false
      ) {
        newSelection.add("all");
      }
      setGroupSelected(newSelection);
    } else {
      setGroupSelected(new Set());
    }
  }, [
    filterValues,
    filter?.defaultToSelectAll,
    filter?.defaultValues,
    filter?.showSelectAll,
  ]);

  useEffect(() => {
    const hasActiveFilters = activeFilterValue.length > 0;
    const userHasInteracted = hasUserInteracted.current;

    if (hasActiveFilters) {
      // URL has filter values - sync component state with URL
      syncWithActiveFilters();
    } else if (userHasInteracted) {
      // URL has no filters but user had interacted - reset component state
      resetComponentState();
    } else {
      // URL has no filters and user hasn't interacted - apply defaults
      applyDefaultValues();
    }
  }, [
    activeFilterValue,
    syncWithActiveFilters,
    resetComponentState,
    applyDefaultValues,
  ]);

  const updateSelection = useCallback(
    (newValues: string[]) => {
      // Mark that user has interacted with the filter
      hasUserInteracted.current = true;

      const actualValues = newValues.filter((key) => key !== "all");
      const newSelection = new Set(actualValues);

      // Auto-add "all" if all items are selected and showSelectAll is not false
      if (
        actualValues.length === filterValues.length &&
        filterValues.length > 0 &&
        filter?.showSelectAll !== false
      ) {
        newSelection.add("all");
      }

      setGroupSelected(newSelection);

      // Notify parent with actual values (excluding "all")
      onFilterChange?.(filter.key, actualValues);
    },
    [filterValues.length, onFilterChange, filter.key, filter?.showSelectAll],
  );

  const onSelectionChange = useCallback(
    (keys: string[]) => {
      const currentSelection = Array.from(groupSelected);
      const newKeys = new Set(keys);
      const oldKeys = new Set(currentSelection);

      // Check if "all" was just toggled
      const allWasSelected = oldKeys.has("all");
      const allIsSelected = newKeys.has("all");

      if (allIsSelected && !allWasSelected) {
        // "all" was just selected - select all items
        updateSelection(filterValues);
      } else if (!allIsSelected && allWasSelected) {
        // "all" was just deselected - deselect all items
        updateSelection([]);
      } else if (allIsSelected && allWasSelected) {
        // "all" was already selected, but individual items changed
        // Remove "all" and keep only the individual selections
        const individualSelections = keys.filter((key) => key !== "all");
        updateSelection(individualSelections);
      } else {
        // Normal individual selection without "all"
        updateSelection(keys);
      }
    },
    [groupSelected, updateSelection, filterValues],
  );

  const handleClearAll = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      updateSelection([]);
    },
    [updateSelection],
  );

  const getDisplayLabel = useCallback(
    (value: string) => {
      const entity: FilterEntity | undefined = filter.valueLabelMapping?.find(
        (entry) => entry[value],
      )?.[value];
      if (!entity) return value;

      if (isScanEntity(entity as ScanEntity)) {
        return (
          (entity as ScanEntity).attributes?.name ||
          (entity as ScanEntity).providerInfo?.alias ||
          (entity as ScanEntity).providerInfo?.uid ||
          value
        );
      } else {
        return (
          (entity as ProviderEntity).alias ||
          (entity as ProviderEntity).uid ||
          value
        );
      }
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
                    <div
                      onClick={handleClearAll}
                      className="ml-1 flex h-4 w-4 flex-shrink-0 cursor-pointer items-center justify-center rounded-full transition-colors hover:bg-default-200"
                      aria-label="Clear selection"
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          handleClearAll(e as unknown as React.MouseEvent);
                        }
                      }}
                    >
                      <X className="h-3 w-3 text-default-400 hover:text-default-600" />
                    </div>
                  </div>
                </>
              )}
            </div>
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-auto min-w-80 dark:bg-prowler-blue-800">
          <div className="flex w-full flex-col gap-4 p-2">
            <CheckboxGroup
              color="default"
              label={filter?.labelCheckboxGroup}
              value={Array.from(groupSelected)}
              onValueChange={onSelectionChange}
              className="font-bold"
            >
              {filterValues.length === 0 && (
                <span className="text-small font-normal">No results found</span>
              )}
              {filter?.showSelectAll !== false && filterValues.length > 0 && (
                <>
                  <Checkbox
                    classNames={{
                      label: "text-small font-normal",
                      wrapper: "checkbox-update",
                    }}
                    value="all"
                  >
                    Select All
                  </Checkbox>
                  <Divider orientation="horizontal" className="mt-2" />
                </>
              )}
              {filterValues.length > 0 && (
                <ScrollShadow
                  hideScrollBar
                  className="flex max-h-96 max-w-full flex-col gap-y-2 py-2"
                >
                  {filterValues.map((value) => {
                    const entity: FilterEntity | undefined =
                      filter.valueLabelMapping?.find((entry) => entry[value])?.[
                        value
                      ];

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
                          isScanEntity(entity as ScanEntity) ? (
                            <ComplianceScanInfo scan={entity as ScanEntity} />
                          ) : (
                            <EntityInfoShort
                              cloudProvider={
                                (entity as ProviderEntity).provider
                              }
                              entityAlias={
                                (entity as ProviderEntity).alias ?? undefined
                              }
                              entityId={(entity as ProviderEntity).uid}
                              hideCopyButton
                            />
                          )
                        ) : (
                          value
                        )}
                      </Checkbox>
                    );
                  })}
                </ScrollShadow>
              )}
            </CheckboxGroup>
          </div>
        </PopoverContent>
      </Popover>
    </div>
  );
};
