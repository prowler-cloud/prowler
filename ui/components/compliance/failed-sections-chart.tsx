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

import { translateType } from "@/lib/ens-compliance";

type FailedSectionItem = {
  name: string;
  total: number;
  types: {
    [key: string]: number;
  };
};

interface FailedSectionsListProps {
  sections: FailedSectionItem[];
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
        return "#868994";
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
    new Set(sections.flatMap((section) => Object.keys(section.types))),
  );

  // Check if there are no failed sections
  if (!sections || sections.length === 0) {
    return (
      <div className="flex w-[400px] flex-col items-center justify-between">
        {title}
        <div className="flex h-[320px] w-full items-center justify-center">
          <p className="text-sm text-gray-500">There are no failed sections</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex w-[600px] flex-col items-center justify-between">
      {title}

      <div className="h-[320px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={chartData}
            layout="vertical"
            margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
            maxBarSize={40}
          >
            <XAxis
              type="number"
              fontSize={12}
              axisLine={false}
              tickLine={false}
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
              contentStyle={{
                backgroundColor: theme === "dark" ? "#1e293b" : "white",
                border: `1px solid ${theme === "dark" ? "#475569" : "rgba(0, 0, 0, 0.1)"}`,
                borderRadius: "6px",
                boxShadow: "0px 4px 12px rgba(0, 0, 0, 0.15)",
                fontSize: "12px",
                padding: "8px 12px",
                color: theme === "dark" ? "white" : "black",
              }}
              formatter={(value: number, name: string) => [
                value,
                translateType(name),
              ]}
              cursor={false}
            />
            <Legend
              formatter={(value) => translateType(value)}
              wrapperStyle={{
                fontSize: "10px",
                display: "flex",
                justifyContent: "center",
                width: "100%",
              }}
              iconType="circle"
              layout="horizontal"
              verticalAlign="bottom"
              height={36}
            />
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
