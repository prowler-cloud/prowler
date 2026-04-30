"use client";

import { type NodeProps } from "@xyflow/react";

import type { GraphNode } from "@/types/attack-paths";

import { resolveNodeColors } from "../../../_lib";
import { HiddenHandles } from "./hidden-handles";

interface InternetNodeData {
  graphNode: GraphNode;
  [key: string]: unknown;
}

const RADIUS = 40; // NODE_HEIGHT * 0.8
const DIAMETER = RADIUS * 2;

export const InternetNode = ({ data, selected }: NodeProps) => {
  const { graphNode } = data as InternetNodeData;
  const { fillColor, borderColor } = resolveNodeColors({
    labels: graphNode.labels,
    properties: graphNode.properties,
    selected,
  });
  const strokeWidth = selected ? 4 : 1.5;

  return (
    <>
      <HiddenHandles />
      <svg width={DIAMETER} height={DIAMETER} className="overflow-visible">
        {/* Main circle */}
        <circle
          cx={RADIUS}
          cy={RADIUS}
          r={RADIUS}
          fill={fillColor}
          fillOpacity={0.85}
          stroke={borderColor}
          strokeWidth={strokeWidth}
          className={selected ? "selected-node" : undefined}
        />
        {/* Horizontal ellipse (equator) */}
        <ellipse
          cx={RADIUS}
          cy={RADIUS}
          rx={RADIUS}
          ry={RADIUS * 0.35}
          fill="none"
          stroke={borderColor}
          strokeWidth={1}
          strokeOpacity={0.5}
        />
        {/* Vertical ellipse (meridian) */}
        <ellipse
          cx={RADIUS}
          cy={RADIUS}
          rx={RADIUS * 0.35}
          ry={RADIUS}
          fill="none"
          stroke={borderColor}
          strokeWidth={1}
          strokeOpacity={0.5}
        />
        {/* Label */}
        <text
          x={RADIUS}
          y={RADIUS}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#ffffff"
          fontSize="11px"
          fontWeight="600"
          style={{ textShadow: "0 1px 2px rgba(0,0,0,0.5)" }}
          pointerEvents="none"
        >
          Internet
        </text>
      </svg>
    </>
  );
};
