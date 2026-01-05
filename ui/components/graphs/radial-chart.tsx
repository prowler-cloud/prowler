"use client";

import {
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

export interface TooltipItem {
  name: string;
  value: number;
  color?: string;
}

interface RadialChartProps {
  percentage: number;
  label?: string;
  color?: string;
  backgroundColor?: string;
  height?: number;
  innerRadius?: number;
  outerRadius?: number;
  startAngle?: number;
  endAngle?: number;
  tooltipData?: TooltipItem[];
}

interface RadialChartTooltipProps {
  active?: boolean;
  payload?: Array<{
    payload?: {
      tooltipData?: TooltipItem[];
    };
  }>;
}

const CustomTooltip = ({ active, payload }: RadialChartTooltipProps) => {
  if (!active || !payload || !payload.length) return null;

  const tooltipItems = payload[0]?.payload?.tooltipData;
  if (
    !tooltipItems ||
    !Array.isArray(tooltipItems) ||
    tooltipItems.length === 0
  )
    return null;

  return (
    <div className="bg-bg-neutral-tertiary border-border-neutral-tertiary rounded-xl border px-3 py-1.5 shadow-lg">
      <div className="flex flex-col gap-0.5">
        {tooltipItems.map((item: TooltipItem, index: number) => (
          <div key={index} className="flex items-end gap-1">
            <p className="text-text-neutral-primary text-xs leading-5 font-medium">
              {item.name}
            </p>
            <div className="border-text-neutral-primary mb-[4px] flex-1 border-b border-dotted" />
            <p
              className="text-xs leading-5 font-medium"
              style={{
                color: item.color || "var(--text-neutral-primary)",
              }}
            >
              {item.value}%
            </p>
          </div>
        ))}
      </div>
    </div>
  );
};

export function RadialChart({
  percentage,
  color = "var(--bg-pass-primary)",
  backgroundColor = "var(--bg-neutral-tertiary)",
  height = 250,
  innerRadius = 60,
  outerRadius = 100,
  startAngle = 90,
  endAngle = -270,
  tooltipData,
}: RadialChartProps) {
  // Calculate the real barSize based on the difference
  const barSize = outerRadius - innerRadius;
  const data = [
    {
      value: percentage,
      tooltipData,
    },
  ];

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RadialBarChart
        cx="50%"
        cy="50%"
        innerRadius={innerRadius}
        outerRadius={outerRadius}
        barSize={barSize}
        data={data}
        startAngle={startAngle}
        endAngle={endAngle}
      >
        <PolarAngleAxis
          type="number"
          domain={[0, 100]}
          angleAxisId={0}
          tick={false}
        />

        {tooltipData && (
          <Tooltip
            content={<CustomTooltip />}
            wrapperStyle={{ zIndex: 1000 }}
            cursor={false}
          />
        )}

        <RadialBar
          background={{ fill: backgroundColor }}
          dataKey="value"
          fill={color}
          cornerRadius={10}
          isAnimationActive={false}
        />

        <text
          x="50%"
          y="38%"
          textAnchor="middle"
          dominantBaseline="middle"
          className="text-2xl font-bold"
          style={{
            fill: "var(--text-neutral-secondary)",
          }}
        >
          {percentage}%
        </text>
      </RadialBarChart>
    </ResponsiveContainer>
  );
}
