"use client";

import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

interface DonutDataPoint {
  name: string;
  value: number;
  color: string;
  percentage?: number;
  new?: number;
  muted?: number;
}

interface DonutChartProps {
  data: DonutDataPoint[];
  height?: number;
  innerRadius?: number;
  outerRadius?: number;
  showLegend?: boolean;
  centerLabel?: {
    value: string | number;
    label: string;
  };
}

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
          className="mb-1 text-sm font-semibold"
          style={{ color: "var(--color-white)" }}
        >
          {data.name}
        </p>
        <p className="text-xs" style={{ color: "var(--color-white)" }}>
          {data.value.toLocaleString()}{" "}
          {data.payload.percentage !== undefined &&
            `(${data.payload.percentage}%)`}
        </p>
        {data.payload.new !== undefined && data.payload.new > 0 && (
          <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
            <span style={{ color: "var(--color-success-emphasis)" }}>↑</span>{" "}
            {data.payload.new} New
          </p>
        )}
        {data.payload.muted !== undefined && data.payload.muted > 0 && (
          <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
            <span style={{ color: "var(--color-warning)" }}>○</span>{" "}
            {data.payload.muted} Muted
          </p>
        )}
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

const CustomLabel = ({
  cx,
  cy,
  value,
  label,
}: {
  cx: number;
  cy: number;
  value: string | number;
  label: string;
}) => {
  return (
    <>
      <text
        x={cx}
        y={cy - 10}
        textAnchor="middle"
        dominantBaseline="middle"
        style={{ fill: "var(--color-white)" }}
        className="text-3xl font-bold"
      >
        {value}
      </text>
      <text
        x={cx}
        y={cy + 15}
        textAnchor="middle"
        dominantBaseline="middle"
        style={{ fill: "var(--color-slate-400)" }}
        className="text-sm"
      >
        {label}
      </text>
    </>
  );
};

export function DonutChart({
  data,
  height = 300,
  innerRadius = 60,
  outerRadius = 100,
  showLegend = true,
  centerLabel,
}: DonutChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={innerRadius}
          outerRadius={outerRadius}
          paddingAngle={2}
          dataKey="value"
          label={false}
        >
          {data.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={entry.color}
              className="transition-opacity hover:opacity-80"
            />
          ))}
        </Pie>
        {centerLabel && (
          <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle">
            <CustomLabel
              cx={0}
              cy={0}
              value={centerLabel.value}
              label={centerLabel.label}
            />
          </text>
        )}
        <Tooltip content={<CustomTooltip />} />
        {showLegend && (
          <Legend
            verticalAlign="bottom"
            height={36}
            iconType="circle"
            formatter={(value, entry: any) => (
              <span className="text-sm" style={{ color: "var(--color-white)" }}>
                {value} ({entry.payload.percentage}%)
              </span>
            )}
          />
        )}
      </PieChart>
    </ResponsiveContainer>
  );
}
