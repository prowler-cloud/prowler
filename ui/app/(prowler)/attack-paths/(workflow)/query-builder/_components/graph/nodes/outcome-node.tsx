"use client";

import { type NodeProps, Position } from "@xyflow/react";
import { Crosshair } from "lucide-react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { GraphNode } from "@/types/attack-paths";

import { OUTCOME_PROPS } from "../../../_lib/group-graph";
import { OUTCOME_NODE_DIMENSIONS } from "../../../_lib/node-dimensions";
import { getNodeLabelDisplay } from "../../../_lib/node-label-lines";

import { HiddenHandles } from "./hidden-handles";

interface OutcomeNodeData {
  graphNode: GraphNode;
  [key: string]: unknown;
}

const NODE_WIDTH = OUTCOME_NODE_DIMENSIONS.WIDTH;
const NODE_HEIGHT = OUTCOME_NODE_DIMENSIONS.HEIGHT;
const NAME_MAX_CHARS = OUTCOME_NODE_DIMENSIONS.LABEL_MAX_CHARS;
const NAME_MAX_LINES = OUTCOME_NODE_DIMENSIONS.LABEL_MAX_LINES;
const BADGE_RADIUS = 24;
const BADGE_CENTER_X = NODE_WIDTH / 2;
const BADGE_CENTER_Y = 26;
const BADGE_LEFT_X = BADGE_CENTER_X - BADGE_RADIUS;
const BADGE_RIGHT_X = BADGE_CENTER_X + BADGE_RADIUS;
const ICON_SIZE = 26;
const ICON_X = BADGE_CENTER_X - ICON_SIZE / 2;
const ICON_Y = BADGE_CENTER_Y - ICON_SIZE / 2;
const TEXT_X = BADGE_CENTER_X;
const KICKER_Y = 64;
const LABEL_Y = 78;
const LABEL_LINE_HEIGHT = 13;

// Distinct terminal styling (orange), independent of the resource palette.
const OUTCOME_FILL = "#c2410c";
const OUTCOME_BORDER = "#f97316";

export const OutcomeNode = ({ data, selected }: NodeProps) => {
  const { graphNode } = data as OutcomeNodeData;
  const label = String(graphNode.properties[OUTCOME_PROPS.LABEL] ?? "Outcome");
  const partial = Boolean(graphNode.properties[OUTCOME_PROPS.PARTIAL]);

  const name = getNodeLabelDisplay(label, NAME_MAX_CHARS, NAME_MAX_LINES);

  const nodeSvg = (
    <svg
      width={NODE_WIDTH}
      height={NODE_HEIGHT}
      className="overflow-visible"
      tabIndex={name.isTruncated ? 0 : undefined}
      data-testid="attack-path-outcome-node"
    >
      <circle
        cx={BADGE_CENTER_X}
        cy={BADGE_CENTER_Y}
        r={BADGE_RADIUS + 5}
        fill={OUTCOME_BORDER}
        fillOpacity={0.22}
        pointerEvents="none"
      />
      <circle
        cx={BADGE_CENTER_X}
        cy={BADGE_CENTER_Y}
        r={BADGE_RADIUS}
        fill={OUTCOME_FILL}
        stroke={OUTCOME_BORDER}
        strokeWidth={selected ? 4 : 2}
        // Partial/latent outcomes are drawn with a dashed ring as a first pass.
        strokeDasharray={partial ? "4 3" : undefined}
      />
      <g
        aria-label="Outcome"
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
        x={TEXT_X}
        y={KICKER_Y}
        textAnchor="middle"
        fontSize="8px"
        fontWeight="700"
        letterSpacing="1"
        fill={OUTCOME_BORDER}
        pointerEvents="none"
      >
        {partial ? "LATENT OUTCOME" : "OUTCOME"}
      </text>
      <text
        x={TEXT_X}
        y={LABEL_Y}
        textAnchor="middle"
        dominantBaseline="middle"
        fill="#ffffff"
        style={{ textShadow: "0 1px 2px rgba(0,0,0,0.5)" }}
        pointerEvents="none"
      >
        {name.lines.map((line, index) => (
          <tspan
            key={`${line}-${index}`}
            x={TEXT_X}
            y={LABEL_Y + index * LABEL_LINE_HEIGHT}
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
        sourceStyle={{ left: BADGE_RIGHT_X, top: BADGE_CENTER_Y }}
        targetPosition={Position.Left}
        targetStyle={{ left: BADGE_LEFT_X, top: BADGE_CENTER_Y }}
      />
      {name.isTruncated ? (
        <Tooltip>
          <TooltipTrigger asChild>{nodeSvg}</TooltipTrigger>
          <TooltipContent>{label}</TooltipContent>
        </Tooltip>
      ) : (
        nodeSvg
      )}
    </>
  );
};
