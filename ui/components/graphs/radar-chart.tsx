"use client";

import { type MouseEvent } from "react";
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

interface TooltipPayloadItem {
  payload: RadarDataPoint;
}

interface TooltipProps {
  active?: boolean;
  payload?: TooltipPayloadItem[];
}

const CustomTooltip = ({ active, payload }: TooltipProps) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary pointer-events-none min-w-[200px] rounded-xl border p-3 shadow-lg">
        <p className="text-text-neutral-primary text-sm font-semibold">
          {data.payload.category}
        </p>
        <div className="mt-1">
          <AlertPill value={data.payload.value} />
        </div>
        {data.payload.change !== undefined && (
          <p className="text-text-neutral-secondary mt-1 text-sm font-medium">
            <span
              style={{
                color:
                  data.payload.change > 0
                    ? "var(--bg-pass-primary)"
                    : "var(--bg-data-critical)",
                fontWeight: "bold",
              }}
            >
              {(data.payload.change as number) > 0 ? "+" : ""}
              {data.payload.change}%{" "}
            </span>
            since last scan
          </p>
        )}
      </div>
    );
  }
  return null;
};

interface DotShapeProps {
  cx: number;
  cy: number;
  payload: RadarDataPoint & { name?: string };
  key: string;
}

interface CustomDotProps extends DotShapeProps {
  selectedPoint?: RadarDataPoint | null;
  onSelectPoint?: (point: RadarDataPoint | null) => void;
  data?: RadarDataPoint[];
}

const CustomDot = ({
  cx,
  cy,
  payload,
  selectedPoint,
  onSelectPoint,
  data,
}: CustomDotProps) => {
  const currentCategory = payload.name || payload.category;
  const isSelected = selectedPoint?.category === currentCategory;
  const isFaded = selectedPoint !== null && !isSelected;

  const handleClick = (e: MouseEvent) => {
    e.stopPropagation();
    if (onSelectPoint) {
      // Re-evaluate selection status at click time, not from closure
      const currentlySelected = selectedPoint?.category === currentCategory;
      if (currentlySelected) {
        onSelectPoint(null);
      } else {
        const fullDataItem = data?.find(
          (d: RadarDataPoint) => d.category === currentCategory,
        );
        const point: RadarDataPoint = {
          category: currentCategory,
          categoryId: fullDataItem?.categoryId || payload.categoryId || "",
          value: payload.value,
          change: payload.change,
          severityData: fullDataItem?.severityData || payload.severityData,
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
      style={{
        fill: isSelected
          ? "var(--bg-button-primary)"
          : "var(--bg-radar-button)",
        fillOpacity: isFaded ? 0.3 : 1,
        cursor: onSelectPoint ? "pointer" : "default",
        pointerEvents: "all",
        transition: "fill-opacity 200ms ease-in-out",
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
          tick={{ fill: "var(--color-text-neutral-primary)" }}
        />
        <PolarGrid strokeOpacity={0.3} />
        <Radar
          dataKey={dataKey}
          fill="var(--bg-radar-map)"
          fillOpacity={1}
          activeDot={false}
          dot={
            onSelectPoint
              ? (dotProps: DotShapeProps) => {
                  const { key, cx, cy, payload } = dotProps;
                  return (
                    <CustomDot
                      key={key}
                      cx={cx}
                      cy={cy}
                      payload={payload}
                      selectedPoint={selectedPoint}
                      onSelectPoint={onSelectPoint}
                      data={data}
                    />
                  );
                }
              : {
                  r: 6,
                  fill: "var(--bg-radar-map)",
                  fillOpacity: 1,
                }
          }
        />
      </RechartsRadar>
    </ChartContainer>
  );
}
