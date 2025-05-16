"use client";

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

export const FailedSectionsChart = ({ sections }: FailedSectionsListProps) => {
  const getTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case "requisito":
        return "#3CEC6D";
      case "recomendacion":
        return "#FB718F";
      case "refuerzo":
        return "#868994";
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

  return (
    <div className="flex flex-col items-center justify-between">
      <h3 className="whitespace-nowrap text-xs font-semibold uppercase tracking-wide">
        Failed Sections (Top 5)
      </h3>

      <div className="h-[320px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={chartData}
            layout="vertical"
            margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
          >
            <XAxis
              type="number"
              fontSize={12}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              width={100}
              tick={{ fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "rgba(255, 255, 255, 0.8)",
                border: "none",
                borderRadius: "8px",
                boxShadow: "0px 2px 8px rgba(0, 0, 0, 0.1)",
                fontSize: "12px",
                padding: "8px",
              }}
              formatter={(value: number, name: string) => [
                value,
                translateType(name),
              ]}
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
