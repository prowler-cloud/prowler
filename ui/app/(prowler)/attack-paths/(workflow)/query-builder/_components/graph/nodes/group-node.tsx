"use client";

import { type NodeProps, Position } from "@xyflow/react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { GraphNode } from "@/types/attack-paths";

import { resolveNodeColors, resolveNodeVisual } from "../../../_lib";
import { RESOURCE_NODE_DIMENSIONS } from "../../../_lib/node-dimensions";
import { HiddenHandles } from "./hidden-handles";

interface GroupNodeData {
  graphNode: GraphNode;
  [key: string]: unknown;
}

const NODE_WIDTH = RESOURCE_NODE_DIMENSIONS.WIDTH;
const NODE_HEIGHT = RESOURCE_NODE_DIMENSIONS.HEIGHT;
const BADGE_SIZE = 48;
const BADGE_RADIUS = BADGE_SIZE / 2;
const BADGE_CENTER_X = NODE_WIDTH / 2;
const BADGE_CENTER_Y = 28;
const BADGE_LEFT_X = BADGE_CENTER_X - BADGE_RADIUS;
const BADGE_RIGHT_X = BADGE_CENTER_X + BADGE_RADIUS;
const ICON_SIZE = 26;
const ICON_X = BADGE_CENTER_X - ICON_SIZE / 2;
const ICON_Y = BADGE_CENTER_Y - ICON_SIZE / 2;
// Count chip sits at the top-right of the badge.
const CHIP_CX = BADGE_CENTER_X + BADGE_RADIUS - 2;
const CHIP_CY = BADGE_CENTER_Y - BADGE_RADIUS + 4;

export const GroupNode = ({ data, selected }: NodeProps) => {
  const { graphNode } = data as GroupNodeData;
  const visual = resolveNodeVisual(graphNode);
  const Icon = visual.Icon;
  const { fillColor, borderColor } = resolveNodeColors({
    labels: graphNode.labels,
    properties: graphNode.properties,
    selected,
  });
  const count = Number(graphNode.properties.count ?? 0);
  const typeLabel = visual.description;

  const nodeSvg = (
    <svg
      width={NODE_WIDTH}
      height={NODE_HEIGHT}
      className="overflow-visible"
      data-testid="attack-path-group-node"
    >
      {/* Stacked-card hint: two offset rounded rects behind the badge to signal
          this single node stands for many resources. */}
      <rect
        x={BADGE_LEFT_X + 6}
        y={BADGE_CENTER_Y - BADGE_RADIUS + 6}
        width={BADGE_SIZE}
        height={BADGE_SIZE}
        rx={12}
        fill={fillColor}
        fillOpacity={0.25}
        stroke={borderColor}
        strokeOpacity={0.4}
      />
      <rect
        x={BADGE_LEFT_X + 3}
        y={BADGE_CENTER_Y - BADGE_RADIUS + 3}
        width={BADGE_SIZE}
        height={BADGE_SIZE}
        rx={12}
        fill={fillColor}
        fillOpacity={0.5}
        stroke={borderColor}
        strokeOpacity={0.6}
      />
      <rect
        x={BADGE_LEFT_X}
        y={BADGE_CENTER_Y - BADGE_RADIUS}
        width={BADGE_SIZE}
        height={BADGE_SIZE}
        rx={12}
        fill={fillColor}
        fillOpacity={0.95}
        stroke={borderColor}
        strokeWidth={selected ? 4 : 1.5}
        className={selected ? "selected-node" : undefined}
      />
      <g
        aria-label={`${typeLabel} group icon`}
        role="img"
        transform={`translate(${ICON_X}, ${ICON_Y})`}
      >
        <Icon
          aria-hidden="true"
          className="rounded-md"
          focusable="false"
          height={ICON_SIZE}
          role="presentation"
          size={ICON_SIZE}
          width={ICON_SIZE}
        />
      </g>
      {/* Count chip */}
      <circle cx={CHIP_CX} cy={CHIP_CY} r={11} fill={borderColor} />
      <text
        x={CHIP_CX}
        y={CHIP_CY}
        textAnchor="middle"
        dominantBaseline="central"
        fontSize="10px"
        fontWeight="700"
        fill="#0b1220"
        pointerEvents="none"
      >
        {count > 99 ? "99+" : count}
      </text>
      <text
        x={BADGE_CENTER_X}
        y={70}
        textAnchor="middle"
        fill="#ffffff"
        style={{ textShadow: "0 1px 2px rgba(0,0,0,0.5)" }}
        pointerEvents="none"
      >
        <tspan x={BADGE_CENTER_X} y={70} fontSize="11px" fontWeight="600">
          {typeLabel}
        </tspan>
        <tspan
          x={BADGE_CENTER_X}
          y={86}
          fontSize="9px"
          fill="rgba(255,255,255,0.85)"
        >
          {count} {count === 1 ? "resource" : "resources"}
        </tspan>
        <tspan
          x={BADGE_CENTER_X}
          y={104}
          fontSize="8px"
          fill="rgba(255,255,255,0.7)"
        >
          click to expand
        </tspan>
      </text>
    </svg>
  );

  return (
    <>
      <HiddenHandles
        sourcePosition={Position.Right}
        sourceStyle={{ left: BADGE_RIGHT_X, top: BADGE_CENTER_Y }}
        targetPosition={Position.Left}
        targetStyle={{ left: BADGE_LEFT_X, top: BADGE_CENTER_Y }}
      />
      <Tooltip>
        <TooltipTrigger asChild>{nodeSvg}</TooltipTrigger>
        <TooltipContent>
          {count} {typeLabel} {count === 1 ? "resource" : "resources"} — click
          to expand
        </TooltipContent>
      </Tooltip>
    </>
  );
};
