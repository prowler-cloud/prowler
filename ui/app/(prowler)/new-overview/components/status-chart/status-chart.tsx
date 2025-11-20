"use client";

import { Bell, ShieldCheck, TriangleAlert } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";

import { DonutChart } from "@/components/graphs/donut-chart";
import { DonutDataPoint } from "@/components/graphs/types";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardVariant,
  ResourceStatsCard,
  Skeleton,
} from "@/components/shadcn";
import { calculatePercentage } from "@/lib/utils";

interface StatusChartProps {
  failFindingsData: {
    total: number;
    new: number;
  };
  passFindingsData: {
    total: number;
    new: number;
  };
  providers?: Array<{
    id: string;
    attributes: {
      uid: string;
      provider: string;
    };
  }>;
}

export const StatusChart = ({
  failFindingsData,
  passFindingsData,
  providers = [],
}: StatusChartProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Calculate total from displayed findings (fail + pass)
  const totalFindings = failFindingsData.total + passFindingsData.total;

  const handleSegmentClick = (dataPoint: DonutDataPoint) => {
    // Build the URL with current filters plus status and muted
    const params = new URLSearchParams(searchParams.toString());

    // Convert filter[provider_id__in] to filter[provider_uid__in] for findings page
    const providerIds = params.get("filter[provider_id__in]");
    if (providerIds) {
      params.delete("filter[provider_id__in]");
      const ids = providerIds.split(",");
      const uids = ids
        .map((id) => {
          const provider = providers.find((p) => p.id === id);
          return provider?.attributes.uid;
        })
        .filter(Boolean);

      if (uids.length > 0) {
        params.set("filter[provider_uid__in]", uids.join(","));
      }
    }

    // Add status filter based on which segment was clicked
    if (dataPoint.name === "Fail Findings") {
      params.set("filter[status__in]", "FAIL");
    } else if (dataPoint.name === "Pass Findings") {
      params.set("filter[status__in]", "PASS");
    }

    // Add exclude muted findings filter
    params.set("filter[muted]", "false");

    // Navigate to findings page
    router.push(`/findings?${params.toString()}`);
  };

  // Calculate percentages
  const failPercentage = calculatePercentage(
    failFindingsData.total,
    totalFindings,
  );
  const passPercentage = calculatePercentage(
    passFindingsData.total,
    totalFindings,
  );

  // Calculate change percentages (new findings as percentage change)
  const failChange = calculatePercentage(
    failFindingsData.new,
    failFindingsData.total,
  );
  const passChange = calculatePercentage(
    passFindingsData.new,
    passFindingsData.total,
  );

  // Mock data for DonutChart
  const donutData: DonutDataPoint[] = [
    {
      name: "Fail Findings",
      value: failFindingsData.total,
      color: "var(--bg-fail-primary)",
      percentage: Number(failPercentage),
      change: Number(failChange),
    },
    {
      name: "Pass Findings",
      value: passFindingsData.total,
      color: "var(--bg-pass-primary)",
      percentage: Number(passPercentage),
      change: Number(passChange),
    },
  ];

  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[312px] flex-1 flex-col justify-between md:min-w-[380px]"
    >
      <CardHeader>
        <CardTitle>Check Findings</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        <div className="mx-auto h-[172px] w-[172px]">
          <DonutChart
            data={donutData}
            showLegend={false}
            innerRadius={66}
            outerRadius={86}
            centerLabel={{
              value: totalFindings.toLocaleString(),
              label: "Total Findings",
            }}
            onSegmentClick={handleSegmentClick}
          />
        </div>

        <Card
          variant="inner"
          padding="md"
          className="flex w-full flex-col items-start justify-center gap-4 lg:flex-row lg:justify-between"
        >
          <ResourceStatsCard
            containerless
            badge={{
              icon: TriangleAlert,
              count: failFindingsData.total,
              variant: CardVariant.fail,
            }}
            label="Fail Findings"
            stats={[{ icon: Bell, label: `${failFindingsData.new} New` }]}
            emptyState={
              failFindingsData.total === 0
                ? { message: "No failed findings to display" }
                : undefined
            }
            className="w-full lg:min-w-0 lg:flex-1"
          />

          <div className="flex w-full items-center justify-center lg:w-auto lg:self-stretch">
            <div className="bg-border-neutral-primary h-px w-full lg:h-full lg:w-px" />
          </div>

          <ResourceStatsCard
            containerless
            badge={{
              icon: ShieldCheck,
              count: passFindingsData.total,
              variant: CardVariant.pass,
            }}
            label="Pass Findings"
            stats={[{ icon: Bell, label: `${passFindingsData.new} New` }]}
            emptyState={
              passFindingsData.total === 0
                ? { message: "No passed findings to display" }
                : undefined
            }
            className="w-full lg:min-w-0 lg:flex-1"
          />
        </Card>
      </CardContent>
    </Card>
  );
};

export function StatusChartSkeleton() {
  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[312px] flex-1 flex-col justify-between md:min-w-[380px]"
    >
      <CardHeader>
        <Skeleton className="h-7 w-[260px] rounded-xl" />
      </CardHeader>

      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        {/* Circular skeleton for donut chart */}
        <div className="mx-auto h-[172px] w-[172px]">
          <Skeleton className="size-[172px] rounded-full" />
        </div>

        {/* Bottom info box skeleton */}
        <Skeleton className="h-[97px] w-full shrink-0 rounded-xl" />
      </CardContent>
    </Card>
  );
}
