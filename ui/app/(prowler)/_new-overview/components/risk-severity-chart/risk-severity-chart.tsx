"use client";

import { useRouter, useSearchParams } from "next/navigation";

import { HorizontalBarChart } from "@/components/graphs/horizontal-bar-chart";
import { BarDataPoint } from "@/components/graphs/types";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Skeleton,
} from "@/components/shadcn";
import { calculatePercentage } from "@/lib/utils";
import { SEVERITY_FILTER_MAP } from "@/types/severities";

interface RiskSeverityChartProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export const RiskSeverityChart = ({
  critical,
  high,
  medium,
  low,
  informational,
}: RiskSeverityChartProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const handleBarClick = (dataPoint: BarDataPoint) => {
    // Build the URL with current filters plus severity and muted
    const params = new URLSearchParams(searchParams.toString());

    // Convert filter[provider_id__in] to filter[provider__in] for findings page
    const providerIds = params.get("filter[provider_id__in]");
    if (providerIds) {
      params.delete("filter[provider_id__in]");
      // Remove provider_type__in since provider__in is more specific
      params.delete("filter[provider_type__in]");
      params.set("filter[provider__in]", providerIds);
    }

    const severity = SEVERITY_FILTER_MAP[dataPoint.name];
    if (severity) {
      params.set("filter[severity__in]", severity);
    }

    // Add exclude muted findings filter
    params.set("filter[muted]", "false");

    // Navigate to findings page
    router.push(`/findings?${params.toString()}`);
  };
  // Calculate total findings
  const totalFindings = critical + high + medium + low + informational;

  // Transform data to BarDataPoint format
  const chartData: BarDataPoint[] = [
    {
      name: "Critical",
      value: critical,
      percentage: calculatePercentage(critical, totalFindings),
    },
    {
      name: "High",
      value: high,
      percentage: calculatePercentage(high, totalFindings),
    },
    {
      name: "Medium",
      value: medium,
      percentage: calculatePercentage(medium, totalFindings),
    },
    {
      name: "Low",
      value: low,
      percentage: calculatePercentage(low, totalFindings),
    },
    {
      name: "Info",
      value: informational,
      percentage: calculatePercentage(informational, totalFindings),
    },
  ];

  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[312px] flex-1 flex-col md:min-w-[380px]"
    >
      <CardHeader>
        <CardTitle>Risk Severity</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-1 items-center justify-start px-6">
        <HorizontalBarChart data={chartData} onBarClick={handleBarClick} />
      </CardContent>
    </Card>
  );
};

export function RiskSeverityChartSkeleton() {
  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[312px] flex-1 flex-col md:min-w-[380px]"
    >
      <CardHeader>
        <Skeleton className="h-7 w-[260px] rounded-xl" />
      </CardHeader>

      <CardContent className="flex flex-1 items-center justify-start px-6">
        <div className="flex w-full flex-col gap-6">
          {/* 5 horizontal bar skeletons */}
          {Array.from({ length: 5 }).map((_, index) => (
            <div key={index} className="flex h-7 w-full gap-6">
              <Skeleton className="h-full w-28 shrink-0 rounded-xl" />
              <Skeleton className="h-full flex-1 rounded-xl" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
