"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { CategoryData } from "@/types/compliance";

import { HeatmapChart } from "./heatmap-chart";

interface SectionsFailureRateCardProps {
  categories: CategoryData[];
}

export function SectionsFailureRateCard({
  categories,
}: SectionsFailureRateCardProps) {
  return (
    <Card variant="base" className="flex min-h-[372px] min-w-[328px] flex-col">
      <CardHeader>
        <CardTitle>Sections Failure Rate</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-1 items-center justify-start">
        <HeatmapChart categories={categories} />
      </CardContent>
    </Card>
  );
}
