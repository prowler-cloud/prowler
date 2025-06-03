"use client";

import { useTheme } from "next-themes";
import {
  Bar,
  BarChart,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { translateType } from "@/lib/compliance/ens";
import { FailedSection } from "@/types/compliance";

interface FailedSectionsListProps {
  sections: FailedSection[];
}

const title = (
  <h3 className="whitespace-nowrap text-xs font-semibold uppercase tracking-wide">
    Failed Sections (Top 5)
  </h3>
);

export const FailedSectionsChart = ({ sections }: FailedSectionsListProps) => {
  const { theme } = useTheme();

  const getTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case "requisito":
        return "#ff5356";
      case "recomendacion":
        return "#FDC53A"; // Increased contrast from #FDDD8A
      case "refuerzo":
        return "#7FB5FF"; // Increased contrast from #B5D7FF
      default:
        return "#ff5356";
    }
  };

  const chartData = [...sections]
    .sort((a, b) => b.total - a.total)
    .slice(0, 5)
    .map((section) => ({
      name: section.name.charAt(0).toUpperCase() + section.name.slice(1),
      ...section.types,
    }));

  const allTypes = Array.from(
    new Set(sections.flatMap((section) => Object.keys(section.types || {}))),
  );

  // Add empty bars to complete up to 5 bars for better distribution
  while (chartData.length < 5) {
    const emptyBar: any = { name: "" };
    allTypes.forEach((type) => {
      emptyBar[type] = 0;
    });
    chartData.push(emptyBar);
  }

  // Calculate the maximum value to ensure proper scaling
  const maxValue = Math.max(
    ...chartData.map((item) =>
      allTypes.reduce((sum, type) => sum + ((item as any)[type] || 0), 0),
    ),
  );

  // Set minimum domain to ensure bars are always visible
  const domainMax = Math.max(maxValue, 1);

  // Check if there are no failed sections
  if (!sections || sections.length === 0) {
    return (
      <div className="flex w-[400px] flex-col items-center justify-between lg:w-[600px]">
        {title}
        <div className="flex h-[320px] w-full items-center justify-center">
          <p className="text-sm text-gray-500">There are no failed sections</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex w-[400px] flex-col items-center justify-between lg:w-[600px]">
      <div className="mt-4">{title}</div>

      <div className="h-[320px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={chartData}
            layout="vertical"
            margin={{ top: 16, right: 30, left: 40, bottom: 5 }}
            maxBarSize={40}
          >
            <XAxis
              type="number"
              fontSize={12}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
              hide={true}
              domain={[0, domainMax]}
              tick={{
                fontSize: 12,
                fill: theme === "dark" ? "#94a3b8" : "#374151",
              }}
            />
            <YAxis
              type="category"
              dataKey="name"
              width={100}
              tick={{
                fontSize: 12,
                fill: theme === "dark" ? "#94a3b8" : "#374151",
              }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              content={(props) => {
                if (!props.active || !props.payload || !props.payload.length) {
                  return null;
                }

                const data = props.payload[0].payload;
                if (!data.name || data.name === "") {
                  return null;
                }

                const hasValues = allTypes.some((type) => data[type] > 0);
                if (!hasValues) {
                  return null;
                }

                return (
                  <div
                    style={{
                      backgroundColor: theme === "dark" ? "#1e293b" : "white",
                      border: `1px solid ${theme === "dark" ? "#475569" : "rgba(0, 0, 0, 0.1)"}`,
                      borderRadius: "6px",
                      boxShadow: "0px 4px 12px rgba(0, 0, 0, 0.15)",
                      fontSize: "12px",
                      padding: "8px 12px",
                      color: theme === "dark" ? "white" : "black",
                    }}
                  >
                    {props.payload.map((entry: any, index: number) => (
                      <div key={index} style={{ color: entry.color }}>
                        {translateType(entry.dataKey)}: {entry.value}
                      </div>
                    ))}
                  </div>
                );
              }}
              cursor={false}
            />
            {allTypes.length > 1 && (
              <Legend
                formatter={(value) => translateType(value)}
                wrapperStyle={{
                  fontSize: "10px",
                  display: "flex",
                  justifyContent: "center",
                  width: "100%",
                  paddingTop: "16px",
                  marginBottom: "4px",
                }}
                iconType="circle"
                layout="horizontal"
                verticalAlign="bottom"
              />
            )}
            {allTypes.map((type, i) => (
              <Bar
                key={type}
                dataKey={type}
                stackId="a"
                fill={getTypeColor(type)}
                radius={i === allTypes.length - 1 ? [0, 4, 4, 0] : [0, 0, 0, 0]}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
