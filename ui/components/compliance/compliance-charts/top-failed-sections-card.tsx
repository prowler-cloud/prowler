"use client";

import { HorizontalBarChart } from "@/components/graphs/horizontal-bar-chart";
import { BarDataPoint } from "@/components/graphs/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import {
  FailedSection,
  TOP_FAILED_DATA_TYPE,
  TopFailedDataType,
} from "@/types/compliance";

interface TopFailedSectionsCardProps {
  sections: FailedSection[];
  dataType?: TopFailedDataType;
}

export function TopFailedSectionsCard({
  sections,
  dataType = TOP_FAILED_DATA_TYPE.SECTIONS,
}: TopFailedSectionsCardProps) {
  // Transform FailedSection[] to BarDataPoint[]
  const total = sections.reduce((sum, section) => sum + section.total, 0);

  const barData: BarDataPoint[] = sections.map((section) => ({
    name: section.name,
    value: section.total,
    percentage: total > 0 ? Math.round((section.total / total) * 100) : 0,
    color: "var(--bg-fail-primary)",
  }));

  const title =
    dataType === TOP_FAILED_DATA_TYPE.REQUIREMENTS
      ? "Top Failed Requirements"
      : "Top Failed Sections";

  return (
    <Card variant="base" className="flex h-full min-h-[372px] w-full flex-col">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-1 items-center justify-start">
        <HorizontalBarChart data={barData} />
      </CardContent>
    </Card>
  );
}
