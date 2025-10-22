"use client";

import {
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart as RechartsRadar,
} from "recharts";

import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
} from "@/components/ui/chart/Chart";

import { AlertPill } from "./shared/alert-pill";
import { CHART_COLORS } from "./shared/constants";
import { RadarDataPoint } from "./types";

interface RadarChartProps {
  data: RadarDataPoint[];
  height?: number;
  dataKey?: string;
  onSelectPoint?: (point: RadarDataPoint | null) => void;
  selectedPoint?: RadarDataPoint | null;
}

const chartConfig = {
  value: {
    label: "Findings",
    color: "var(--chart-radar-primary)",
  },
} satisfies ChartConfig;

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div
        className="rounded-lg border p-3 shadow-lg"
        style={{
          borderColor: CHART_COLORS.tooltipBorder,
          backgroundColor: CHART_COLORS.tooltipBackground,
        }}
      >
        <p
          className="text-sm font-semibold"
          style={{ color: CHART_COLORS.textPrimary }}
        >
          {data.payload.category}
        </p>
        <div className="mt-1">
          <AlertPill value={data.value} />
        </div>
        {data.payload.change !== undefined && (
          <p
            className="mt-1 text-xs"
            style={{ color: CHART_COLORS.textSecondary }}
          >
            <span className="font-bold">
              {data.payload.change > 0 ? "+" : ""}
              {data.payload.change}%
            </span>{" "}
            Since Last Scan
          </p>
        )}
      </div>
    );
  }
  return null;
};

const CustomDot = (props: any) => {
  const { cx, cy, payload, selectedPoint, onSelectPoint } = props;
  const currentCategory = payload.category || payload.name;
  const isSelected = selectedPoint?.category === currentCategory;

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onSelectPoint) {
      if (isSelected) {
        onSelectPoint(null);
      } else {
        const point = {
          category: currentCategory,
          value: payload.value,
          change: payload.change,
        };
        onSelectPoint(point);
      }
    }
  };

  return (
    <circle
      cx={cx}
      cy={cy}
      r={isSelected ? 9 : 6}
      fill={
        isSelected ? "var(--chart-success-color)" : "var(--chart-radar-primary)"
      }
      fillOpacity={1}
      className={isSelected ? "drop-shadow-[0_0_8px_#86da26]" : ""}
      style={{
        cursor: onSelectPoint ? "pointer" : "default",
        pointerEvents: "all",
      }}
      onClick={onSelectPoint ? handleClick : undefined}
    />
  );
};

export function RadarChart({
  data,
  height = 400,
  dataKey = "value",
  onSelectPoint,
  selectedPoint,
}: RadarChartProps) {
  return (
    <ChartContainer
      config={chartConfig}
      className="mx-auto w-full"
      style={{ height }}
    >
      <RechartsRadar data={data}>
        <ChartTooltip cursor={false} content={<CustomTooltip />} />
        <PolarAngleAxis
          dataKey="category"
          tick={{ fill: CHART_COLORS.textPrimary }}
        />
        <PolarGrid strokeOpacity={0.3} />
        <Radar
          dataKey={dataKey}
          fill="var(--chart-radar-primary)"
          fillOpacity={0.2}
          activeDot={false}
          dot={
            onSelectPoint
              ? (dotProps: any) => {
                  const { key, ...rest } = dotProps;
                  return (
                    <CustomDot
                      key={key}
                      {...rest}
                      selectedPoint={selectedPoint}
                      onSelectPoint={onSelectPoint}
                    />
                  );
                }
              : {
                  r: 6,
                  fill: "var(--chart-radar-primary)",
                  fillOpacity: 1,
                }
          }
        />
      </RechartsRadar>
    </ChartContainer>
  );
}
