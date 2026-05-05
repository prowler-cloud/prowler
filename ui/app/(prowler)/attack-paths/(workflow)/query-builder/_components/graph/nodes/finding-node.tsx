"use client";

import { type NodeProps } from "@xyflow/react";

import type { GraphNode } from "@/types/attack-paths";

import { resolveNodeColors, truncateLabel } from "../../../_lib";
import { HiddenHandles } from "./hidden-handles";

interface FindingNodeData {
  graphNode: GraphNode;
  [key: string]: unknown;
}

const HEXAGON_WIDTH = 200;
const HEXAGON_HEIGHT = 55;
const TITLE_MAX_CHARS = 24;

export const FindingNode = ({ data, selected }: NodeProps) => {
  const { graphNode } = data as FindingNodeData;
  const { fillColor, borderColor } = resolveNodeColors({
    labels: graphNode.labels,
    properties: graphNode.properties,
    selected,
  });

  const title = String(
    graphNode.properties?.check_title ||
      graphNode.properties?.name ||
      graphNode.properties?.id ||
      "Finding",
  );
  const displayTitle = truncateLabel(title, TITLE_MAX_CHARS);

  // Hexagon SVG path
  const w = HEXAGON_WIDTH;
  const h = HEXAGON_HEIGHT;
  const sideInset = w * 0.15;
  const hexPath = `
    M ${sideInset} 0
    L ${w - sideInset} 0
    L ${w} ${h / 2}
    L ${w - sideInset} ${h}
    L ${sideInset} ${h}
    L 0 ${h / 2}
    Z
  `;

  return (
    <>
      <HiddenHandles />
      <svg
        width={w}
        height={h}
        className="overflow-visible"
        style={{ filter: selected ? undefined : "url(#glow)" }}
      >
        <path
          d={hexPath}
          fill={fillColor}
          fillOpacity={0.85}
          stroke={borderColor}
          strokeWidth={selected ? 4 : 2}
          className={selected ? "selected-node" : undefined}
        />
        <text
          x={w / 2}
          y={h / 2}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#ffffff"
          fontSize="11px"
          fontWeight="600"
          style={{ textShadow: "0 1px 2px rgba(0,0,0,0.5)" }}
          pointerEvents="none"
        >
          {displayTitle}
        </text>
      </svg>
    </>
  );
};
