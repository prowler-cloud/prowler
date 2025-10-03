"use client";

import { Rectangle, ResponsiveContainer, Sankey, Tooltip } from "recharts";

interface SankeyNode {
  name: string;
}

interface SankeyLink {
  source: number;
  target: number;
  value: number;
}

interface SankeyChartProps {
  data: {
    nodes: SankeyNode[];
    links: SankeyLink[];
  };
  height?: number;
}

const COLORS: Record<string, string> = {
  // Status colors
  Success: "#86DA26", // Green
  Fail: "#DB2B49", // Red

  // Provider colors
  AWS: "#FF9800", // Amber/Orange 500
  Azure: "#06B6D4", // Cyan 500
  Google: "#EF4444", // Red 500

  // Severity colors
  Critical: "#971348", // Dark Red
  High: "#FF3077", // Pink
  Medium: "#FF7D19", // Orange
  Low: "#FDD34F", // Yellow
  Info: "#2E51B2", // Blue
  Informational: "#2E51B2", // Blue
};

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="rounded-lg border border-slate-700 bg-slate-800 p-3 shadow-lg">
        <p className="text-sm font-semibold text-white">{data.name}</p>
        {data.value && (
          <p className="text-xs text-slate-400">Value: {data.value}</p>
        )}
      </div>
    );
  }
  return null;
};

const CustomNode = ({ x, y, width, height, payload, containerWidth }: any) => {
  const isOut = x + width + 6 > containerWidth;
  const nodeName = payload.name;
  const color = COLORS[nodeName] || "#6B7280";

  return (
    <g>
      <Rectangle
        x={x}
        y={y}
        width={width}
        height={height}
        fill={color}
        fillOpacity="1"
      />
      <text
        textAnchor={isOut ? "end" : "start"}
        x={isOut ? x - 6 : x + width + 6}
        y={y + height / 2}
        fontSize="14"
        stroke="#CBD5E1"
        fill="#CBD5E1"
      >
        {nodeName}
      </text>
      <text
        textAnchor={isOut ? "end" : "start"}
        x={isOut ? x - 6 : x + width + 6}
        y={y + height / 2 + 13}
        fontSize="12"
        stroke="#64748B"
        fill="#64748B"
        strokeOpacity="0.5"
      >
        {payload.value}
      </text>
    </g>
  );
};

const CustomLink = (props: any) => {
  const {
    sourceX,
    targetX,
    sourceY,
    targetY,
    sourceControlX,
    targetControlX,
    linkWidth,
  } = props;

  // Determine color based on source node
  const sourceName = props.payload.source?.name || "";
  const color = COLORS[sourceName] || "#6B7280";

  return (
    <g>
      <path
        d={`
          M${sourceX},${sourceY + linkWidth / 2}
          C${sourceControlX},${sourceY + linkWidth / 2}
            ${targetControlX},${targetY + linkWidth / 2}
            ${targetX},${targetY + linkWidth / 2}
          L${targetX},${targetY - linkWidth / 2}
          C${targetControlX},${targetY - linkWidth / 2}
            ${sourceControlX},${sourceY - linkWidth / 2}
            ${sourceX},${sourceY - linkWidth / 2}
          Z
        `}
        fill={color}
        fillOpacity="0.4"
        stroke="none"
      />
    </g>
  );
};

export function SankeyChart({ data, height = 400 }: SankeyChartProps) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <Sankey
        data={data}
        node={<CustomNode />}
        link={<CustomLink />}
        nodePadding={50}
        margin={{ top: 20, right: 160, bottom: 20, left: 160 }}
      >
        <Tooltip content={<CustomTooltip />} />
      </Sankey>
    </ResponsiveContainer>
  );
}
