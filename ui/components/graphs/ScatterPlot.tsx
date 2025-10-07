"use client";

import {
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

interface ScatterDataPoint {
  x: number;
  y: number;
  provider: string;
  name: string;
  size?: number;
}

interface ScatterPlotProps {
  data: ScatterDataPoint[];
  xLabel?: string;
  yLabel?: string;
  height?: number;
  onSelectPoint?: (point: ScatterDataPoint | null) => void;
  selectedPoint?: ScatterDataPoint | null;
}

const PROVIDER_COLORS = {
  AWS: "var(--color-orange)",
  Azure: "var(--color-cyan)",
  Google: "var(--color-red)",
};

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
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
          {data.name}
        </p>
        <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
          Risk Score: {data.x}
        </p>
        <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
          Failed Findings: {data.y}
        </p>
        <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
          Provider: {data.provider}
        </p>
      </div>
    );
  }
  return null;
};

const CustomScatterDot = ({
  cx,
  cy,
  payload,
  selectedPoint,
  onSelectPoint,
}: any) => {
  const isSelected = selectedPoint?.name === payload.name;
  const size = isSelected ? 18 : 8;
  const fill = isSelected
    ? "var(--color-success)"
    : PROVIDER_COLORS[payload.provider as keyof typeof PROVIDER_COLORS] ||
      "#6B7280";

  return (
    <circle
      cx={cx}
      cy={cy}
      r={size / 2}
      fill={fill}
      stroke={isSelected ? "var(--color-success)" : "transparent"}
      strokeWidth={2}
      style={{ cursor: "pointer" }}
      onClick={() => onSelectPoint?.(payload)}
    />
  );
};

export function ScatterPlot({
  data,
  xLabel = "Risk Score",
  yLabel = "Failed Findings",
  height = 400,
  onSelectPoint,
  selectedPoint,
}: ScatterPlotProps) {
  const handlePointClick = (point: ScatterDataPoint) => {
    if (onSelectPoint) {
      // Toggle selection: if clicking the same point, deselect it
      if (selectedPoint?.name === point.name) {
        onSelectPoint(null);
      } else {
        onSelectPoint(point);
      }
    }
  };
  // Group data by provider
  const dataByProvider = data.reduce(
    (acc, point) => {
      const provider = point.provider;
      if (!acc[provider]) {
        acc[provider] = [];
      }
      acc[provider].push(point);
      return acc;
    },
    {} as Record<string, ScatterDataPoint[]>,
  );

  return (
    <ResponsiveContainer width="100%" height={height}>
      <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-slate-700)" />
        <XAxis
          type="number"
          dataKey="x"
          name={xLabel}
          label={{
            value: xLabel,
            position: "insideBottom",
            offset: -10,
            fill: "var(--color-slate-400)",
          }}
          tick={{ fill: "var(--color-slate-400)" }}
          domain={[0, 10]}
        />
        <YAxis
          type="number"
          dataKey="y"
          name={yLabel}
          label={{
            value: yLabel,
            angle: -90,
            position: "insideLeft",
            fill: "var(--color-slate-400)",
          }}
          tick={{ fill: "var(--color-slate-400)" }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Legend
          wrapperStyle={{ paddingTop: "20px" }}
          iconType="circle"
          formatter={(value) => (
            <span className="text-sm" style={{ color: "var(--color-white)" }}>
              {value}
            </span>
          )}
        />
        {Object.entries(dataByProvider).map(([provider, points]) => (
          <Scatter
            key={provider}
            name={provider}
            data={points}
            fill={
              PROVIDER_COLORS[provider as keyof typeof PROVIDER_COLORS] ||
              "#6B7280"
            }
            shape={(props: any) => (
              <CustomScatterDot
                {...props}
                selectedPoint={selectedPoint}
                onSelectPoint={handlePointClick}
              />
            )}
          />
        ))}
      </ScatterChart>
    </ResponsiveContainer>
  );
}
