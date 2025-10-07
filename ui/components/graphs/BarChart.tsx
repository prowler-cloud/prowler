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
  Info: "var(--color-info)",
  Informational: "var(--color-info)",
  Low: "var(--color-warning)",
  Medium: "var(--color-warning-emphasis)",
  High: "var(--color-danger)",
  Critical: "var(--color-danger-emphasis)",
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
          className="mb-1 text-sm font-semibold"
          style={{ color: "var(--color-white)" }}
        >
          {data.name}
        </p>
        <p className="text-xs" style={{ color: "var(--color-white)" }}>
          {data.value.toLocaleString()}{" "}
          {data.percentage !== undefined && `(${data.percentage}%)`}
        </p>
        {data.newFindings !== undefined && (
          <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
            <span style={{ color: "var(--color-destructive)" }}>△</span>{" "}
            {data.newFindings} New Findings
          </p>
        )}
        {data.change !== undefined && (
          <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
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
      fill="var(--color-slate-400)"
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
          stroke="var(--color-slate-700)"
          horizontal={isHorizontal}
          vertical={!isHorizontal}
        />
        {isHorizontal ? (
          <>
            <XAxis
              type="number"
              tick={{ fill: "var(--color-slate-400)", fontSize: 12 }}
              label={
                xLabel
                  ? {
                      value: xLabel,
                      position: "insideBottom",
                      offset: -10,
                      fill: "var(--color-slate-400)",
                    }
                  : undefined
              }
            />
            <YAxis
              dataKey="name"
              type="category"
              width={100}
              tick={{ fill: "var(--color-slate-400)", fontSize: 12 }}
              label={
                yLabel
                  ? {
                      value: yLabel,
                      angle: -90,
                      position: "insideLeft",
                      fill: "var(--color-slate-400)",
                    }
                  : undefined
              }
            />
          </>
        ) : (
          <>
            <XAxis
              dataKey="name"
              tick={{ fill: "var(--color-slate-400)", fontSize: 12 }}
              label={
                xLabel
                  ? {
                      value: xLabel,
                      position: "insideBottom",
                      offset: -10,
                      fill: "var(--color-slate-400)",
                    }
                  : undefined
              }
            />
            <YAxis
              type="number"
              tick={{ fill: "var(--color-slate-400)", fontSize: 12 }}
              label={
                yLabel
                  ? {
                      value: yLabel,
                      angle: -90,
                      position: "insideLeft",
                      fill: "var(--color-slate-400)",
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
