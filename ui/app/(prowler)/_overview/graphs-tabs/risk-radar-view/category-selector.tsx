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
    if (value === "" || value === "all") {
      onCategoryChange(null);
    } else {
      onCategoryChange(value);
    }
  };

  return (
    <Select value={selectedCategory ?? "all"} onValueChange={handleValueChange}>
      <SelectTrigger size="sm" className="w-[200px]">
        <SelectValue placeholder="All categories" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">All categories</SelectItem>
        {categories.map((category) => (
          <SelectItem key={category.categoryId} value={category.categoryId}>
            {category.category}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
