"use client";

import React, { useCallback } from "react";

import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";

interface CustomDropdownSelectionProps {
  label: string;
  name: string;
  values: { id: string; name: string }[];
  onChange: (name: string, selectedValues: string[]) => void;
  selectedKeys?: string[];
}

export const CustomDropdownSelection: React.FC<
  CustomDropdownSelectionProps
> = ({ label, name, values, onChange, selectedKeys = [] }) => {
  const handleValuesChange = useCallback(
    (newValues: string[]) => {
      onChange(name, newValues);
    },
    [name, onChange],
  );

  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm font-medium">{label}</p>
      <MultiSelect values={selectedKeys} onValuesChange={handleValuesChange}>
        <MultiSelectTrigger>
          <MultiSelectValue placeholder={`Select ${label.toLowerCase()}`} />
        </MultiSelectTrigger>
        <MultiSelectContent
          search={{
            placeholder: `Search ${label.toLowerCase()}...`,
            emptyMessage: "No results found",
          }}
        >
          {values.map((item) => (
            <MultiSelectItem key={item.id} value={item.id}>
              {item.name}
            </MultiSelectItem>
          ))}
        </MultiSelectContent>
      </MultiSelect>
    </div>
  );
};
