"use client";

import { useState } from "react";
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

import { AlertPill } from "@/components/graphs/shared/alert-pill";
import { ChartLegend } from "@/components/graphs/shared/chart-legend";
import { CHART_COLORS } from "@/components/graphs/shared/constants";
import { getSeverityColorByRiskScore } from "@/components/graphs/shared/utils";

// Mock data - Risk Score (0-10) vs Failed Findings count
const mockScatterData = [
  { x: 9.2, y: 1456, provider: "AWS", name: "Amazon RDS" },
  { x: 8.5, y: 892, provider: "AWS", name: "Amazon EC2" },
  { x: 7.1, y: 445, provider: "AWS", name: "Amazon S3" },
  { x: 6.3, y: 678, provider: "AWS", name: "AWS Lambda" },
  { x: 4.2, y: 156, provider: "AWS", name: "AWS Backup" },
  { x: 8.8, y: 1023, provider: "Azure", name: "Azure SQL Database" },
  { x: 7.9, y: 834, provider: "Azure", name: "Azure Virtual Machines" },
  { x: 6.4, y: 567, provider: "Azure", name: "Azure Storage" },
  { x: 5.1, y: 289, provider: "Azure", name: "Azure Key Vault" },
  { x: 7.6, y: 712, provider: "Google", name: "Cloud SQL" },
  { x: 6.9, y: 623, provider: "Google", name: "Compute Engine" },
  { x: 5.8, y: 412, provider: "Google", name: "Cloud Storage" },
  { x: 4.5, y: 198, provider: "Google", name: "Cloud Run" },
  { x: 8.9, y: 945, provider: "AWS", name: "Amazon RDS Aurora" },
];

const PROVIDER_COLORS = {
  AWS: "#ff9900",
  Azure: "#00bcd4",
  Google: "#EA4335",
};

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    const severityColor = getSeverityColorByRiskScore(data.x);

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
          {data.name}
        </p>
        <p
          className="mt-1 text-xs"
          style={{ color: CHART_COLORS.textSecondary }}
        >
          <span style={{ color: severityColor }}>{data.x}</span> Risk Score
        </p>
        <div className="mt-2">
          <AlertPill value={data.y} />
        </div>
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
    ? "#86DA26"
    : PROVIDER_COLORS[payload.provider as keyof typeof PROVIDER_COLORS] ||
      CHART_COLORS.defaultColor;

  return (
    <circle
      cx={cx}
      cy={cy}
      r={size / 2}
      fill={fill}
      stroke={isSelected ? "#86DA26" : "transparent"}
      strokeWidth={2}
      className={isSelected ? "drop-shadow-[0_0_8px_#86da26]" : ""}
      style={{ cursor: "pointer" }}
      onClick={() => onSelectPoint?.(payload)}
    />
  );
};

const CustomLegend = ({ payload }: any) => {
  const items = payload.map((entry: any) => ({
    label: entry.value,
    color: entry.color,
  }));

  return <ChartLegend items={items} />;
};

export function RiskPlotView() {
  const [selectedPoint, setSelectedPoint] = useState<any>(null);

  const dataByProvider = mockScatterData.reduce(
    (acc, point) => {
      const provider = point.provider;
      if (!acc[provider]) {
        acc[provider] = [];
      }
      acc[provider].push(point);
      return acc;
    },
    {} as Record<string, typeof mockScatterData>,
  );

  const handleSelectPoint = (point: any) => {
    if (selectedPoint?.name === point.name) {
      setSelectedPoint(null);
    } else {
      setSelectedPoint(point);
    }
  };

  return (
    <div className="w-full flex-1 overflow-hidden">
      <ResponsiveContainer width="100%" height={460}>
      <ScatterChart margin={{ top: 20, right: 30, bottom: 60, left: 60 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={CHART_COLORS.gridLine} />
        <XAxis
          type="number"
          dataKey="x"
          name="Risk Score"
          label={{
            value: "Risk Score",
            position: "bottom",
            offset: 10,
            fill: CHART_COLORS.textSecondary,
          }}
          tick={{ fill: CHART_COLORS.textSecondary }}
          domain={[0, 10]}
        />
        <YAxis
          type="number"
          dataKey="y"
          name="Failed Findings"
          label={{
            value: "Failed Findings",
            angle: -90,
            position: "left",
            offset: 10,
            fill: CHART_COLORS.textSecondary,
          }}
          tick={{ fill: CHART_COLORS.textSecondary }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Legend content={<CustomLegend />} />
        {Object.entries(dataByProvider).map(([provider, points]) => (
          <Scatter
            key={provider}
            name={provider}
            data={points}
            fill={
              PROVIDER_COLORS[provider as keyof typeof PROVIDER_COLORS] ||
              CHART_COLORS.defaultColor
            }
            shape={(props: any) => (
              <CustomScatterDot
                {...props}
                selectedPoint={selectedPoint}
                onSelectPoint={handleSelectPoint}
              />
            )}
          />
        ))}
      </ScatterChart>
    </ResponsiveContainer>
    </div>
  );
}
