"use client";

import type { RadarDataPoint } from "@/components/graphs/types";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";

interface CategorySelectorProps {
  categories: RadarDataPoint[];
  selectedCategory: string | null;
  onCategoryChange: (categoryId: string | null) => void;
}

export function CategorySelector({
  categories,
  selectedCategory,
  onCategoryChange,
}: CategorySelectorProps) {
  const handleValueChange = (value: string) => {
    if (value === "") {
      onCategoryChange(null);
    } else {
      onCategoryChange(value);
    }
  };

  return (
    <Select
      value={selectedCategory ?? ""}
      onValueChange={handleValueChange}
      allowDeselect
    >
      <SelectTrigger size="sm" className="w-[200px]">
        <SelectValue placeholder="All categories" />
      </SelectTrigger>
      <SelectContent>
        {categories.map((category) => (
          <SelectItem key={category.categoryId} value={category.categoryId}>
            {category.category}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
