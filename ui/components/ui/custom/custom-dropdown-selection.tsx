"use client";

import React, { useCallback, useEffect, useMemo } from "react";

import {
  Select,
  SelectAllItem,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";

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
  const allValues = useMemo(() => values.map((item) => item.id), [values]);

  const handleMultiValueChange = useCallback(
    (newValues: string[]) => {
      onChange(name, newValues);
    },
    [name, onChange],
  );

  // Sync internal state when selectedKeys prop changes
  useEffect(() => {
    // This ensures the component updates when parent changes selectedKeys
  }, [selectedKeys]);

  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm font-medium">{label}</p>
      <Select
        multiple
        selectedValues={selectedKeys}
        onMultiValueChange={handleMultiValueChange}
        ariaLabel={label}
      >
        <SelectTrigger>
          <SelectValue placeholder={`Select ${label.toLowerCase()}`}>
            {selectedKeys.length > 0
              ? `${selectedKeys.length} ${selectedKeys.length > 1 ? "items" : "item"} selected`
              : `Select ${label.toLowerCase()}`}
          </SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectAllItem allValues={allValues} />
          {values.map((item) => (
            <SelectItem key={item.id} value={item.id}>
              {item.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
};
