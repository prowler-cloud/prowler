"use client";

import { type NodeProps, Position } from "@xyflow/react";
import { Crosshair } from "lucide-react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { GraphNode } from "@/types/attack-paths";

import {
  GRAPH_NODE_BORDER_COLORS,
  GRAPH_NODE_COLORS,
} from "../../../_lib/graph-colors";
import { RESOURCE_NODE_DIMENSIONS } from "../../../_lib/node-dimensions";
import { getNodeLabelDisplay } from "../../../_lib/node-label-lines";
import { HiddenHandles } from "./hidden-handles";

interface OutcomeNodeData {
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
const ICON_SIZE = 26;
const ICON_X = BADGE_CENTER_X - ICON_SIZE / 2;
const ICON_Y = BADGE_CENTER_Y - ICON_SIZE / 2;
const NAME_Y = 72;
const NAME_LINE_HEIGHT = 13;

type Severity = keyof typeof GRAPH_NODE_COLORS;

const resolveSeverityColors = (
  severity: string,
): { fill: string; border: string } => {
  const key = severity.toLowerCase() as Severity;
  if (key in GRAPH_NODE_COLORS) {
    return {
      fill: GRAPH_NODE_COLORS[key],
      border: GRAPH_NODE_BORDER_COLORS[key as keyof typeof GRAPH_NODE_BORDER_COLORS],
    };
  }
  return { fill: GRAPH_NODE_COLORS.high, border: GRAPH_NODE_BORDER_COLORS.high };
};

export const OutcomeNode = ({ data, selected }: NodeProps) => {
  const { graphNode } = data as OutcomeNodeData;
  const label = String(graphNode.properties.label ?? "Outcome");
  const description = String(graphNode.properties.description ?? "");
  const severity = String(graphNode.properties.severity ?? "high");
  const { fill, border } = resolveSeverityColors(severity);

  const displayName = getNodeLabelDisplay(label, 18, 3);

  const nodeSvg = (
    <svg
      width={NODE_WIDTH}
      height={NODE_HEIGHT}
      className="overflow-visible"
      data-testid="attack-path-outcome-node"
    >
      <circle
        cx={BADGE_CENTER_X}
        cy={BADGE_CENTER_Y}
        r={BADGE_RADIUS + 4}
        fill={border}
        fillOpacity={0.22}
        pointerEvents="none"
      />
      <circle
        cx={BADGE_CENTER_X}
        cy={BADGE_CENTER_Y}
        r={BADGE_RADIUS}
        fill={fill}
        fillOpacity={0.95}
        stroke={border}
        strokeWidth={selected ? 4 : 2}
        className={selected ? "selected-node" : undefined}
      />
      <g
        aria-label="Attack outcome icon"
        role="img"
        transform={`translate(${ICON_X}, ${ICON_Y})`}
      >
        <Crosshair
          aria-hidden="true"
          color="#ffffff"
          focusable="false"
          height={ICON_SIZE}
          role="presentation"
          size={ICON_SIZE}
          width={ICON_SIZE}
        />
      </g>
      <text
        x={BADGE_CENTER_X}
        y={NAME_Y}
        textAnchor="middle"
        fill="#ffffff"
        style={{ textShadow: "0 1px 2px rgba(0,0,0,0.5)" }}
        pointerEvents="none"
      >
        <tspan
          x={BADGE_CENTER_X}
          y={NAME_Y - NAME_LINE_HEIGHT}
          fontSize="8px"
          fill="rgba(255,255,255,0.75)"
          letterSpacing="0.05em"
        >
          OUTCOME
        </tspan>
        {displayName.lines.map((line, index) => (
          <tspan
            key={`${line}-${index}`}
            x={BADGE_CENTER_X}
            y={NAME_Y + index * NAME_LINE_HEIGHT}
            fontSize="11px"
            fontWeight="700"
          >
            {line}
          </tspan>
        ))}
      </text>
    </svg>
  );

  return (
    <>
      <HiddenHandles
        sourcePosition={Position.Right}
        targetPosition={Position.Left}
        targetStyle={{ left: BADGE_LEFT_X, top: BADGE_CENTER_Y }}
      />
      <Tooltip>
        <TooltipTrigger asChild>{nodeSvg}</TooltipTrigger>
        <TooltipContent>
          <span className="font-semibold">{label}</span>
          {description ? <span className="block text-xs">{description}</span> : null}
        </TooltipContent>
      </Tooltip>
    </>
  );
};
