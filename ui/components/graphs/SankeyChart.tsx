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
  Success: "var(--color-success)",
  Fail: "var(--color-destructive)",

  // Provider colors
  AWS: "var(--color-orange)",
  Azure: "var(--color-cyan)",
  Google: "var(--color-red)",

  // Severity colors
  Critical: "var(--color-danger-emphasis)",
  High: "var(--color-danger)",
  Medium: "var(--color-warning-emphasis)",
  Low: "var(--color-warning)",
  Info: "var(--color-info)",
  Informational: "var(--color-info)",
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
          className="text-sm font-semibold"
          style={{ color: "var(--color-white)" }}
        >
          {data.name}
        </p>
        {data.value && (
          <p className="text-xs" style={{ color: "var(--color-slate-400)" }}>
            Value: {data.value}
          </p>
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
        stroke="var(--color-white)"
        fill="var(--color-white)"
      >
        {nodeName}
      </text>
      <text
        textAnchor={isOut ? "end" : "start"}
        x={isOut ? x - 6 : x + width + 6}
        y={y + height / 2 + 13}
        fontSize="12"
        stroke="var(--color-slate-400)"
        fill="var(--color-slate-400)"
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
