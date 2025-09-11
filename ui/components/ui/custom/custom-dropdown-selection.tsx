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

  const allValues = useMemo(() => values.map((item) => item.id), [values]);

  // Update internal state when selectedKeys changes
  useEffect(() => {
    const newSelection = new Set(selectedKeys);
    if (selectedKeys.length === allValues.length) {
      newSelection.add("all");
    }
    setSelectedValues(newSelection);
  }, [selectedKeys, allValues]);

  const onSelectionChange = useCallback(
    (keys: string[]) => {
      const newSelection = new Set(keys);

      if (newSelection.has("all")) {
        // Handle "Select All" behavior
        if (newSelection.size === allValues.length + 1) {
          setSelectedValues(new Set(["all", ...allValues]));
          onChange(name, allValues); // Exclude "all" in the callback
        } else {
          newSelection.delete("all");
          setSelectedValues(newSelection);
          onChange(name, Array.from(newSelection));
        }
      } else {
        setSelectedValues(newSelection);
        onChange(name, Array.from(newSelection));
      }
    },
    [allValues, name, onChange],
  );

  const handleSelectAllClick = useCallback(() => {
    if (selectedValues.has("all")) {
      setSelectedValues(new Set());
      onChange(name, []);
    } else {
      const newSelection = new Set(["all", ...allValues]);
      setSelectedValues(newSelection);
      onChange(name, allValues);
    }
  }, [allValues, name, onChange, selectedValues]);

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
                classNames={{
                  label: "text-small font-normal",
                  wrapper: "checkbox-update",
                }}
                value="all"
                isSelected={selectedValues.has("all")}
                onChange={handleSelectAllClick}
              >
                Select All
              </Checkbox>
              <Divider orientation="horizontal" className="mt-2" />
              <ScrollShadow
                hideScrollBar
                className="flex max-h-96 max-w-56 flex-col gap-y-2 py-2"
              >
                {values.map(({ id, name }) => (
                  <Checkbox
                    classNames={{
                      label: "text-small font-normal",
                      wrapper: "checkbox-update",
                    }}
                    key={id}
                    value={id}
                  >
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
