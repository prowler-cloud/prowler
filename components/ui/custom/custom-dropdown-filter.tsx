"use client";

import {
  Button,
  Checkbox,
  CheckboxGroup,
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@nextui-org/react";
import React, { useCallback, useState } from "react";

import { PlusCircleIcon } from "@/components/icons";

interface FilterOption {
  key: string;
  labelCheckboxGroup: string;
  values: string[];
}

interface CustomDropdownFilterProps {
  filter?: FilterOption;
}

export const CustomDropdownFilter: React.FC<CustomDropdownFilterProps> = ({
  filter,
}) => {
  // Early return if filter is undefined
  if (!filter) {
    return null;
  }

  const [groupSelected, setGroupSelected] = useState(new Set<string>());

  const allFilterKeys = filter.values || [];

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
    },
    [allFilterKeys, groupSelected],
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
      <Popover placement="bottom">
        <PopoverTrigger>
          <Button
            className="bg-default-100 text-default-800"
            startContent={
              <PlusCircleIcon className="text-default-400" width={16} />
            }
            size="sm"
          >
            {filter.key}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-80">
          <div className="flex w-full flex-col gap-6 px-2 py-4">
            <CheckboxGroup
              label={filter.labelCheckboxGroup}
              value={Array.from(groupSelected)}
              onValueChange={onSelectionChange}
            >
              <Checkbox
                value="all"
                // isSelected={allSelected}
                onValueChange={handleSelectAllClick}
              >
                Select All
              </Checkbox>
              {allFilterKeys.map((value) => (
                <Checkbox key={value} value={value}>
                  {value}
                </Checkbox>
              ))}
            </CheckboxGroup>
          </div>
        </PopoverContent>
      </Popover>
      <p className="text-small text-default-500">
        Selected:{" "}
        {Array.from(groupSelected)
          .filter((item) => item !== "all")
          .join(", ")}
      </p>
    </div>
  );
};
