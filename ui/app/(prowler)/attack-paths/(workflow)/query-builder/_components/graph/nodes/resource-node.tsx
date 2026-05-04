"use client";

import { type NodeProps } from "@xyflow/react";

import type { GraphNode } from "@/types/attack-paths";

import { resolveNodeColors, truncateLabel } from "../../../_lib";
import { formatNodeLabel } from "../../../_lib/format";
import { HiddenHandles } from "./hidden-handles";

interface ResourceNodeData {
  graphNode: GraphNode;
  hasFindings?: boolean;
  [key: string]: unknown;
}

const NODE_WIDTH = 180;
const NODE_HEIGHT = 50;
const NODE_RADIUS = 25;
const NAME_MAX_CHARS = 22;

export const ResourceNode = ({ data, selected }: NodeProps) => {
  const { graphNode, hasFindings } = data as ResourceNodeData;
  const { fillColor, borderColor } = resolveNodeColors({
    labels: graphNode.labels,
    properties: graphNode.properties,
    selected,
    hasFindings,
  });
  const strokeWidth = selected ? 4 : hasFindings ? 2.5 : 1.5;

  const name = String(
    graphNode.properties?.name ||
      graphNode.properties?.id ||
      (graphNode.labels.length > 0
        ? formatNodeLabel(graphNode.labels[0])
        : "Unknown"),
  );
  const displayName = truncateLabel(name, NAME_MAX_CHARS);

  const typeLabel =
    graphNode.labels.length > 0 ? formatNodeLabel(graphNode.labels[0]) : "";

  return (
    <>
      <HiddenHandles />
      <svg width={NODE_WIDTH} height={NODE_HEIGHT} className="overflow-visible">
        <rect
          x={0}
          y={0}
          width={NODE_WIDTH}
          height={NODE_HEIGHT}
          rx={NODE_RADIUS}
          ry={NODE_RADIUS}
          fill={fillColor}
          fillOpacity={0.85}
          stroke={borderColor}
          strokeWidth={strokeWidth}
          className={selected ? "selected-node" : undefined}
        />
        <text
          x={NODE_WIDTH / 2}
          y={NODE_HEIGHT / 2}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#ffffff"
          style={{ textShadow: "0 1px 2px rgba(0,0,0,0.5)" }}
          pointerEvents="none"
        >
          <tspan
            x={NODE_WIDTH / 2}
            dy="-0.3em"
            fontSize="11px"
            fontWeight="600"
          >
            {displayName}
          </tspan>
          {typeLabel && (
            <tspan
              x={NODE_WIDTH / 2}
              dy="1.3em"
              fontSize="9px"
              fill="rgba(255,255,255,0.8)"
            >
              {typeLabel}
            </tspan>
          )}
        </text>
      </svg>
    </>
  );
};
