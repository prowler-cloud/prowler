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

interface RadarDataPoint {
  category: string;
  value: number;
  change?: number;
}

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
    color: "var(--color-magenta)",
  },
} satisfies ChartConfig;

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div
        className="rounded-lg border p-3 shadow-lg"
        style={{
          borderColor: "var(--color-slate-700)",
          backgroundColor: "var(--color-slate-800)",
        }}
      >
        <p
          className="text-sm font-semibold"
          style={{ color: "var(--color-white)" }}
        >
          {data.payload.category}
        </p>
        <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
          <span style={{ color: "var(--color-magenta)" }}>▲</span> {data.value}{" "}
          Fail Findings
        </p>
        {data.payload.change !== undefined && (
          <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
            {data.payload.change > 0 ? "+" : ""}
            {data.payload.change}% Since last scan
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
      fill={isSelected ? "var(--color-success)" : "var(--color-purple-dark)"}
      fillOpacity={1}
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
          tick={{ fill: "var(--color-white)" }}
        />
        <PolarGrid strokeOpacity={0.3} />
        <Radar
          dataKey={dataKey}
          fill="var(--color-magenta)"
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
                  fill: "var(--color-purple-dark)",
                  fillOpacity: 1,
                }
          }
        />
      </RechartsRadar>
    </ChartContainer>
  );
}
