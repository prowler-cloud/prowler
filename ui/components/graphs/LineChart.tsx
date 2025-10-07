"use client";

import {
  CartesianGrid,
  Legend,
  Line,
  LineChart as RechartsLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

interface LineDataPoint {
  date: string;
  [key: string]: string | number;
}

interface LineChartProps {
  data: LineDataPoint[];
  lines: Array<{
    dataKey: string;
    color: string;
    label: string;
  }>;
  xLabel?: string;
  yLabel?: string;
  height?: number;
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div
        className="rounded-lg border p-3 shadow-lg"
        style={{
          borderColor: "var(--color-slate-700)",
          backgroundColor: "var(--color-slate-800)",
        }}
      >
        <p
          className="mb-2 text-sm font-semibold"
          style={{ color: "var(--color-white)" }}
        >
          {label}
        </p>
        {payload.map((entry: any, index: number) => (
          <div key={index} className="flex items-center gap-2">
            <div
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: entry.color }}
            />
            <span className="text-xs" style={{ color: "var(--color-white)" }}>
              {entry.name}:
            </span>
            <span
              className="text-xs font-semibold"
              style={{ color: "var(--color-white)" }}
            >
              {entry.value}
            </span>
            {entry.payload[`${entry.dataKey}_change`] && (
              <span
                className="text-xs"
                style={{ color: "var(--color-slate-400)" }}
              >
                ({entry.payload[`${entry.dataKey}_change`] > 0 ? "+" : ""}
                {entry.payload[`${entry.dataKey}_change`]}%)
              </span>
            )}
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export function LineChart({
  data,
  lines,
  xLabel,
  yLabel,
  height = 400,
}: LineChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <RechartsLine
        data={data}
        margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-slate-700)" />
        <XAxis
          dataKey="date"
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
          tick={{ fill: "var(--color-slate-400)", fontSize: 12 }}
        />
        <YAxis
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
          tick={{ fill: "var(--color-slate-400)", fontSize: 12 }}
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
        {lines.map((line) => (
          <Line
            key={line.dataKey}
            type="monotone"
            dataKey={line.dataKey}
            stroke={line.color}
            strokeWidth={2}
            name={line.label}
            dot={{ fill: line.color, r: 4 }}
            activeDot={{ r: 6 }}
          />
        ))}
      </RechartsLine>
    </ResponsiveContainer>
  );
}
