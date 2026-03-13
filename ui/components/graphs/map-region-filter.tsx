"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select/Select";

interface MapRegionFilterProps {
  regions: string[];
  selectedRegion: string;
  onRegionChange: (region: string) => void;
  chartColors: {
    tooltipBorder: string;
    tooltipBackground: string;
    textPrimary: string;
  };
}

export function MapRegionFilter({
  regions,
  selectedRegion,
  onRegionChange,
  chartColors,
}: MapRegionFilterProps) {
  return (
    <Select value={selectedRegion} onValueChange={onRegionChange}>
      <SelectTrigger
        className="min-w-[200px] rounded-lg"
        style={{
          borderColor: chartColors.tooltipBorder,
          backgroundColor: chartColors.tooltipBackground,
          color: chartColors.textPrimary,
        }}
      >
        <SelectValue placeholder="All Regions" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="All Regions">All Regions</SelectItem>
        {regions.map((region) => (
          <SelectItem key={region} value={region}>
            {region}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
