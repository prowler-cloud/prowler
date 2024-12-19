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
import React, { useCallback, useEffect, useMemo, useState } from "react";

import { PlusCircleIcon } from "@/components/icons";

interface CustomDropdownSelectionProps {
  label: string;
  name: string;
  values: { id: string; name: string }[];
  onChange: (name: string, selectedValues: string[]) => void;
  selectedKeys?: string[];
}

const selectedTagClass =
  "inline-flex items-center border py-1 text-xs transition-colors border-transparent bg-default-500 text-secondary-foreground hover:bg-default-500/80 rounded-md px-2 font-normal";

export const CustomDropdownSelection: React.FC<
  CustomDropdownSelectionProps
> = ({ label, name, values, onChange, selectedKeys = [] }) => {
  const [selectedValues, setSelectedValues] = useState<Set<string>>(
    new Set(selectedKeys),
  );
  const allValues = values.map((item) => item.id);

  const memoizedValues = useMemo(() => values, [values]);

  // Update the internal state when selectedKeys changes from props
  useEffect(() => {
    const newSelection = new Set(selectedKeys);
    if (
      JSON.stringify(Array.from(selectedValues)) !==
      JSON.stringify(Array.from(newSelection))
    ) {
      if (selectedKeys.length === allValues.length) {
        newSelection.add("all");
      }
      setSelectedValues(newSelection);
    }
  }, [selectedKeys]);

  const onSelectionChange = useCallback(
    (keys: string[]) => {
      setSelectedValues((prevSelected) => {
        const newSelection = new Set(keys);

        // If all values are selected and "all" is not included,
        // add "all" automatically
        if (
          newSelection.size === allValues.length &&
          !newSelection.has("all")
        ) {
          return new Set(["all", ...allValues]);
        } else if (prevSelected.has("all")) {
          // If "all" was previously selected, remove it
          newSelection.delete("all");
          return new Set(allValues.filter((key) => newSelection.has(key)));
        }
        return newSelection;
      });

      // Notify the change without including "all"
      const selectedValues = keys.filter((key) => key !== "all");
      onChange(name, selectedValues);
    },
    [allValues, name, onChange],
  );

  const handleSelectAllClick = useCallback(() => {
    setSelectedValues((prevSelected: Set<string>) => {
      const newSelection: Set<string> = prevSelected.has("all")
        ? new Set()
        : new Set(["all", ...allValues]);

      // Notify the change without including "all"
      const selectedValues = Array.from(newSelection).filter(
        (key) => key !== "all",
      );
      onChange(name, selectedValues);

      return newSelection;
    });
  }, [allValues, name, onChange]);

  return (
    <div className="relative flex w-full flex-col gap-2">
      <Popover backdrop="transparent" placement="bottom-start">
        <PopoverTrigger>
          <Button
            className="border-input hover:bg-accent hover:text-accent-foreground inline-flex h-10 items-center justify-center whitespace-nowrap rounded-md border border-dashed bg-background px-3 text-xs font-medium shadow-sm transition-colors focus-visible:outline-none disabled:opacity-50 dark:bg-prowler-blue-800"
            startContent={<PlusCircleIcon size={16} />}
            size="md"
          >
            <h3 className="text-small">{label}</h3>
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-80 dark:bg-prowler-blue-800">
          <div className="flex w-full flex-col gap-6 p-2">
            <CheckboxGroup
              color="default"
              label={label}
              value={Array.from(selectedValues)}
              onValueChange={onSelectionChange}
              className="font-bold"
            >
              <Checkbox
                className="font-normal"
                value="all"
                onClick={handleSelectAllClick}
              >
                Select All
              </Checkbox>
              <Divider orientation="horizontal" className="mt-2" />
              <ScrollShadow
                hideScrollBar
                className="flex max-h-96 max-w-56 flex-col gap-y-2 py-2"
              >
                {memoizedValues.map(({ id, name }) => (
                  <Checkbox className="font-normal" key={id} value={id}>
                    {name}
                  </Checkbox>
                ))}
              </ScrollShadow>
            </CheckboxGroup>
          </div>
        </PopoverContent>
      </Popover>

      {/* Selected Values Display */}
      {selectedValues.size > 0 && (
        <div className="mt-2 flex flex-wrap gap-2">
          {Array.from(selectedValues)
            .filter((value) => value !== "all")
            .map((value) => {
              const selectedItem = values.find((item) => item.id === value);
              return (
                <span key={value} className={selectedTagClass}>
                  {selectedItem?.name || value}
                </span>
              );
            })}
        </div>
      )}
    </div>
  );
};
