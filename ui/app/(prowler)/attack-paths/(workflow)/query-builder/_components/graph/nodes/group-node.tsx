"use client";

import { type NodeProps } from "@xyflow/react";

import type { GraphNode } from "@/types/attack-paths";

import {
  GRAPH_COUNT_BADGE_STROKE_COLOR,
  resolveNodeColors,
  resolveNodeVisual,
} from "../../../_lib";
import { GROUP_PROPS } from "../../../_lib/group-graph";
import { GROUP_NODE_DIMENSIONS } from "../../../_lib/node-dimensions";
import { getNodeLabelDisplay } from "../../../_lib/node-label-lines";

import { GraphNodeShell } from "./graph-node-shell";

interface GroupNodeData {
  graphNode: GraphNode;
  [key: string]: unknown;
}

const NODE_WIDTH = GROUP_NODE_DIMENSIONS.WIDTH;
const NODE_HEIGHT = GROUP_NODE_DIMENSIONS.HEIGHT;
const NAME_MAX_CHARS = GROUP_NODE_DIMENSIONS.LABEL_MAX_CHARS;
const NAME_MAX_LINES = GROUP_NODE_DIMENSIONS.LABEL_MAX_LINES;
const BADGE_SIZE = 44;
const BADGE_RADIUS = BADGE_SIZE / 2;
const BADGE_CENTER_X = NODE_WIDTH / 2;
const BADGE_CENTER_Y = 26;
const ICON_SIZE = 28;
const ICON_X = BADGE_CENTER_X - ICON_SIZE / 2;
const ICON_Y = BADGE_CENTER_Y - ICON_SIZE / 2;
// Count badge, top-right of the class icon.
const COUNT_CX = BADGE_CENTER_X + BADGE_RADIUS - 2;
const COUNT_CY = BADGE_CENTER_Y - BADGE_RADIUS + 2;
const COUNT_R = 11;
const TEXT_X = BADGE_CENTER_X;
const NAME_Y = 62;
const NAME_LINE_HEIGHT = 13;
const COUNT_LABEL_Y = 96;
const HINT_Y = 112;

export const GroupNode = ({ data, selected }: NodeProps) => {
  const { graphNode } = data as GroupNodeData;
  const classLabel = String(graphNode.properties[GROUP_PROPS.CLASS] ?? "");
  const className = String(graphNode.properties[GROUP_PROPS.CLASS_NAME] ?? "");
  const count = Number(graphNode.properties[GROUP_PROPS.COUNT] ?? 0);
  // Members carry findings -> red cue, so the user knows to expand (matches the
  // per-resource "red = findings" convention).
  const hasFindings = Boolean(graphNode.properties[GROUP_PROPS.HAS_FINDINGS]);

  // Resolve the class icon/colors from a representative node of the class.
  const representative: GraphNode = {
    id: graphNode.id,
    labels: [classLabel],
    properties: {},
  };
  const visual = resolveNodeVisual(representative);
  const Icon = visual.Icon;
  const { fillColor, borderColor } = resolveNodeColors({
    labels: [classLabel],
    properties: {},
    selected,
    hasFindings,
  });

  const fullName = className || visual.description;
  const name = getNodeLabelDisplay(fullName, NAME_MAX_CHARS, NAME_MAX_LINES);

  return (
    <GraphNodeShell
      width={NODE_WIDTH}
      height={NODE_HEIGHT}
      badgeCenterX={BADGE_CENTER_X}
      badgeCenterY={BADGE_CENTER_Y}
      badgeRadius={BADGE_RADIUS}
      testId="attack-path-group-node"
      svgClassName="cursor-pointer"
      tooltip={name.isTruncated ? fullName : undefined}
    >
      {hasFindings && (
        <circle
          cx={BADGE_CENTER_X}
          cy={BADGE_CENTER_Y}
          r={BADGE_RADIUS + 5}
          fill={borderColor}
          fillOpacity={0.26}
          pointerEvents="none"
        />
      )}
      <circle
        cx={BADGE_CENTER_X}
        cy={BADGE_CENTER_Y}
        r={BADGE_RADIUS}
        fill={fillColor}
        fillOpacity={0.92}
        stroke={borderColor}
        strokeWidth={selected ? 4 : hasFindings ? 3 : 1.5}
      />
      <g
        aria-label={`${visual.description} icon`}
        role="img"
        transform={`translate(${ICON_X}, ${ICON_Y})`}
      >
        <Icon
          aria-hidden="true"
          focusable="false"
          height={ICON_SIZE}
          role="presentation"
          size={ICON_SIZE}
          width={ICON_SIZE}
        />
      </g>
      {/* count badge */}
      <circle
        cx={COUNT_CX}
        cy={COUNT_CY}
        r={COUNT_R}
        fill={borderColor}
        stroke={GRAPH_COUNT_BADGE_STROKE_COLOR}
        strokeWidth={2}
      />
      <text
        x={COUNT_CX}
        y={COUNT_CY + 1}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize="11px"
        fontWeight="700"
        fill="#ffffff"
        pointerEvents="none"
      >
        {count}
      </text>
      <text
        x={TEXT_X}
        y={NAME_Y}
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
            y={NAME_Y + index * NAME_LINE_HEIGHT}
            fontSize="11px"
            fontWeight="600"
          >
            {line}
          </tspan>
        ))}
      </text>
      <text
        x={TEXT_X}
        y={COUNT_LABEL_Y}
        textAnchor="middle"
        fontSize="9px"
        fill="rgba(255,255,255,0.8)"
        pointerEvents="none"
      >
        {count} {count === 1 ? "resource" : "resources"}
      </text>
      <text
        x={TEXT_X}
        y={HINT_Y}
        textAnchor="middle"
        fontSize="8px"
        fill="rgba(255,255,255,0.55)"
        pointerEvents="none"
      >
        click to expand
      </text>
    </GraphNodeShell>
  );
};
