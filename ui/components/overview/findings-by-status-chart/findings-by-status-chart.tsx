"use client";

import { Card, CardBody } from "@nextui-org/react";
import { Chip } from "@nextui-org/react";
import { TrendingUp } from "lucide-react";
import Link from "next/link";
import React, { useMemo } from "react";
import { Label, Pie, PieChart } from "recharts";

import { NotificationIcon, SuccessIcon } from "@/components/icons";
import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart/Chart";

const calculatePercent = (
  chartData: { findings: string; number: number; fill: string }[],
) => {
  const total = chartData.reduce((sum, item) => sum + item.number, 0);

  return chartData.map((item) => ({
    ...item,
    percent: total > 0 ? Math.round((item.number / total) * 100) + "%" : "0%",
  }));
};

interface FindingsByStatusChartProps {
  findingsByStatus: {
    data: {
      attributes: {
        fail: number;
        pass: number;
        pass_new: number;
        fail_new: number;
        total: number;
      };
    };
  };
}

const chartConfig = {
  number: {
    label: "Findings",
  },
  success: {
    label: "Success",
    color: "hsl(var(--chart-success))",
  },
  fail: {
    label: "Fail",
    color: "hsl(var(--chart-fail))",
  },
} satisfies ChartConfig;

export const FindingsByStatusChart: React.FC<FindingsByStatusChartProps> = ({
  findingsByStatus,
}) => {
  const {
    fail = 0,
    pass = 0,
    pass_new = 0,
    fail_new = 0,
  } = findingsByStatus?.data?.attributes || {};
  const chartData = [
    {
      findings: "Success",
      number: pass,
      fill: "var(--color-success)",
    },
    {
      findings: "Fail",
      number: fail,
      fill: "var(--color-fail)",
    },
  ];

  const updatedChartData = calculatePercent(chartData);

  const totalFindings = useMemo(
    () => chartData.reduce((acc, curr) => acc + curr.number, 0),
    [chartData],
  );

  const emptyChartData = [
    {
      findings: "Empty",
      number: 1,
      fill: "hsl(var(--nextui-default-200))",
    },
  ];

  return (
    <Card className="h-full dark:bg-prowler-blue-400">
      <CardBody>
        <div className="flex flex-col items-center gap-6">
          <ChartContainer
            config={chartConfig}
            className="aspect-square w-[250px] min-w-[250px]"
          >
            <PieChart>
              <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
              <Pie
                data={totalFindings > 0 ? chartData : emptyChartData}
                dataKey="number"
                nameKey="findings"
                innerRadius={65}
                strokeWidth={55}
              >
                <Label
                  content={({ viewBox }) => {
                    if (viewBox && "cx" in viewBox && "cy" in viewBox) {
                      return (
                        <text
                          x={viewBox.cx}
                          y={viewBox.cy}
                          textAnchor="middle"
                          dominantBaseline="middle"
                        >
                          <tspan
                            x={viewBox.cx}
                            y={viewBox.cy}
                            className="fill-foreground text-xl font-bold"
                          >
                            {totalFindings > 0
                              ? totalFindings.toLocaleString()
                              : "0"}
                          </tspan>
                          <tspan
                            x={viewBox.cx}
                            y={(viewBox.cy || 0) + 20}
                            className="fill-foreground text-xs"
                          >
                            Findings
                          </tspan>
                        </text>
                      );
                    }
                  }}
                />
              </Pie>
            </PieChart>
          </ChartContainer>

          <div className="grid w-full grid-cols-2 justify-items-center gap-6">
            <div className="flex flex-col gap-2">
              <div className="flex items-center space-x-2 self-end">
                <Link
                  href="/findings?filter[status]=PASS"
                  className="flex items-center space-x-2"
                >
                  <Chip
                    className="h-5"
                    variant="flat"
                    startContent={<SuccessIcon size={18} />}
                    color="success"
                    radius="lg"
                    size="md"
                  >
                    {chartData[0].number}
                  </Chip>
                  <span>{updatedChartData[0].percent}</span>
                </Link>
              </div>
              <div className="text-muted-foreground flex items-center gap-1 text-xs font-medium leading-none">
                {pass_new > 0 ? (
                  <>
                    +{pass_new} pass findings from last day{" "}
                    <TrendingUp className="h-4 w-4" />
                  </>
                ) : pass_new < 0 ? (
                  <>{pass_new} pass findings from last day</>
                ) : (
                  "No change from last day"
                )}
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <div className="flex items-center align-middle">
                <Link
                  href="/findings?filter[status]=FAIL"
                  className="flex items-center space-x-2"
                >
                  <Chip
                    className="h-5"
                    variant="flat"
                    startContent={<NotificationIcon size={18} />}
                    color="danger"
                    radius="lg"
                    size="md"
                  >
                    {chartData[1].number}
                  </Chip>
                  <span>{updatedChartData[1].percent}</span>
                </Link>
              </div>
              <div className="text-muted-foreground flex items-center gap-1 text-xs font-medium leading-none">
                +{fail_new} fail findings from last day{" "}
                <TrendingUp className="h-4 w-4" />
              </div>
            </div>
          </div>
        </div>
      </CardBody>
    </Card>
  );
};
