"use client";

import { HorizontalBarChart } from "@/components/graphs/horizontal-bar-chart";
import { BarDataPoint } from "@/components/graphs/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { FailedSection } from "@/types/compliance";

interface TopFailedSectionsCardProps {
  sections: FailedSection[];
}

export function TopFailedSectionsCard({
  sections,
}: TopFailedSectionsCardProps) {
  // Transform FailedSection[] to BarDataPoint[]
  const total = sections.reduce((sum, section) => sum + section.total, 0);

  const barData: BarDataPoint[] = sections.map((section) => ({
    name: section.name,
    value: section.total,
    percentage: total > 0 ? Math.round((section.total / total) * 100) : 0,
    color: "var(--bg-fail-primary)",
  }));

  return (
    <Card
      variant="base"
      className="flex min-h-[372px] w-full flex-col sm:min-w-[500px]"
    >
      <CardHeader>
        <CardTitle>Top Failed Sections</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-1 items-center justify-start">
        <HorizontalBarChart data={barData} labelWidth="w-60" />
      </CardContent>
    </Card>
  );
}
