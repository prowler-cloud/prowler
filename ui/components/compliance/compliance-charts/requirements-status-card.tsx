"use client";

import { ShieldCheck, TriangleAlert, User } from "lucide-react";

import { DonutChart } from "@/components/graphs/donut-chart";
import { DonutDataPoint } from "@/components/graphs/types";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardVariant,
  ResourceStatsCard,
} from "@/components/shadcn";
import { calculatePercentage } from "@/lib/utils";

interface RequirementsStatusCardProps {
  pass: number;
  fail: number;
  manual: number;
}

export function RequirementsStatusCard({
  pass,
  fail,
  manual,
}: RequirementsStatusCardProps) {
  const total = pass + fail + manual;

  const passPercentage = calculatePercentage(pass, total);
  const failPercentage = calculatePercentage(fail, total);
  const manualPercentage = calculatePercentage(manual, total);

  const donutData: DonutDataPoint[] = [
    {
      name: "Pass",
      value: pass,
      color: "var(--bg-pass-primary)",
      percentage: Number(passPercentage),
    },
    {
      name: "Fail",
      value: fail,
      color: "var(--bg-fail-primary)",
      percentage: Number(failPercentage),
    },
    {
      name: "Manual",
      value: manual,
      color: "var(--color-bg-data-muted)",
      percentage: Number(manualPercentage),
    },
  ];

  return (
    <Card
      variant="base"
      className="flex h-full min-h-[372px] flex-col justify-between xl:max-w-[400px]"
    >
      <CardHeader>
        <CardTitle>Requirements Status</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        <div className="mx-auto h-[172px] w-[172px]">
          <DonutChart
            data={donutData}
            showLegend={false}
            innerRadius={66}
            outerRadius={86}
            centerLabel={{
              value: total.toLocaleString(),
              label: "Total",
            }}
          />
        </div>

        <Card
          variant="inner"
          className="flex w-full flex-col items-center justify-around md:flex-row"
        >
          <ResourceStatsCard
            containerless
            badge={{
              icon: ShieldCheck,
              count: pass,
              variant: CardVariant.pass,
            }}
            label="Pass"
            emptyState={
              pass === 0 ? { message: "No passed requirements" } : undefined
            }
            className="w-full"
          />

          <ResourceStatsCard
            containerless
            badge={{
              icon: TriangleAlert,
              count: fail,
              variant: CardVariant.fail,
            }}
            label="Fail"
            emptyState={
              fail === 0 ? { message: "No failed requirements" } : undefined
            }
            className="w-full"
          />

          <ResourceStatsCard
            containerless
            badge={{
              icon: User,
              count: manual,
              variant: CardVariant.default,
            }}
            label="Manual"
            emptyState={
              manual === 0 ? { message: "No manual requirements" } : undefined
            }
            className="w-full"
          />
        </Card>
      </CardContent>
    </Card>
  );
}
