"use client";

import {
  Bar,
  BarChart as RechartsBar,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

interface BarDataPoint {
  name: string;
  value: number;
  percentage?: number;
  color?: string;
  change?: number;
  newFindings?: number;
}

interface BarChartProps {
  data: BarDataPoint[];
  layout?: "horizontal" | "vertical";
  xLabel?: string;
  yLabel?: string;
  height?: number;
  showValues?: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  Info: "#2E51B2", // Blue (Informational)
  Informational: "#2E51B2", // Blue
  Low: "#FDD34F", // Yellow
  Medium: "#FF7D19", // Orange
  High: "#FF3077", // Pink
  Critical: "#971348", // Dark Red
};

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="rounded-lg border border-slate-700 bg-slate-800 p-3 shadow-lg">
        <p className="mb-1 text-sm font-semibold text-white">{data.name}</p>
        <p className="text-xs text-slate-300">
          {data.value.toLocaleString()}{" "}
          {data.percentage !== undefined && `(${data.percentage}%)`}
        </p>
        {data.newFindings !== undefined && (
          <p className="text-xs text-slate-400">
            <span className="text-red-400">△</span> {data.newFindings} New
            Findings
          </p>
        )}
        {data.change !== undefined && (
          <p className="text-xs text-slate-400">
            {data.change > 0 ? "+" : ""}
            {data.change}% Since last scan
          </p>
        )}
      </div>
    );
  }
  return null;
};

const CustomLabel = ({ x, y, width, height, value, data }: any) => {
  const percentage = data.percentage;
  return (
    <text
      x={x + width + 10}
      y={y + height / 2}
      fill="#94A3B8"
      fontSize={12}
      textAnchor="start"
      dominantBaseline="middle"
    >
      {percentage !== undefined
        ? `${percentage}% • ${value.toLocaleString()}`
        : value.toLocaleString()}
    </text>
  );
};

export function BarChart({
  data,
  layout = "horizontal",
  xLabel,
  yLabel,
  height = 400,
  showValues = true,
}: BarChartProps) {
  const isHorizontal = layout === "horizontal";

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RechartsBar
        data={data}
        layout={layout}
        margin={{ top: 20, right: showValues ? 100 : 30, left: 20, bottom: 20 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="#334155"
          horizontal={isHorizontal}
          vertical={!isHorizontal}
        />
        {isHorizontal ? (
          <>
            <XAxis
              type="number"
              tick={{ fill: "#94A3B8", fontSize: 12 }}
              label={
                xLabel
                  ? {
                      value: xLabel,
                      position: "insideBottom",
                      offset: -10,
                      fill: "#94A3B8",
                    }
                  : undefined
              }
            />
            <YAxis
              dataKey="name"
              type="category"
              width={100}
              tick={{ fill: "#94A3B8", fontSize: 12 }}
              label={
                yLabel
                  ? {
                      value: yLabel,
                      angle: -90,
                      position: "insideLeft",
                      fill: "#94A3B8",
                    }
                  : undefined
              }
            />
          </>
        ) : (
          <>
            <XAxis
              dataKey="name"
              tick={{ fill: "#94A3B8", fontSize: 12 }}
              label={
                xLabel
                  ? {
                      value: xLabel,
                      position: "insideBottom",
                      offset: -10,
                      fill: "#94A3B8",
                    }
                  : undefined
              }
            />
            <YAxis
              type="number"
              tick={{ fill: "#94A3B8", fontSize: 12 }}
              label={
                yLabel
                  ? {
                      value: yLabel,
                      angle: -90,
                      position: "insideLeft",
                      fill: "#94A3B8",
                    }
                  : undefined
              }
            />
          </>
        )}
        <Tooltip content={<CustomTooltip />} />
        <Bar
          dataKey="value"
          radius={4}
          label={
            showValues && isHorizontal
              ? (props: any) => (
                  <CustomLabel {...props} data={data[props.index]} />
                )
              : false
          }
        >
          {data.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={entry.color || SEVERITY_COLORS[entry.name] || "#6B7280"}
              opacity={1}
              className="transition-opacity hover:opacity-80"
            />
          ))}
        </Bar>
      </RechartsBar>
    </ResponsiveContainer>
  );
}
