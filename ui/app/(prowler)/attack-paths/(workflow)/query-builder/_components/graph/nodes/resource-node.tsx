"use client";

import { type NodeProps, Position } from "@xyflow/react";

import type { GraphNode } from "@/types/attack-paths";

import { resolveNodeColors, resolveNodeVisual } from "../../../_lib";
import { HiddenHandles } from "./hidden-handles";
import { getNodeLabelLines } from "./node-label-lines";

interface ResourceNodeData {
  graphNode: GraphNode;
  hasFindings?: boolean;
  [key: string]: unknown;
}

const NODE_WIDTH = 136;
const NODE_HEIGHT = 112;
const NAME_MAX_CHARS = 16;
const NAME_MAX_LINES = 2;
const BADGE_SIZE = 44;
const BADGE_RADIUS = BADGE_SIZE / 2;
const BADGE_CENTER_X = NODE_WIDTH / 2;
const BADGE_CENTER_Y = 26;
const BADGE_BOTTOM_Y = BADGE_CENTER_Y + BADGE_RADIUS;
const BADGE_TOP_Y = BADGE_CENTER_Y - BADGE_RADIUS;
const ICON_SIZE = 28;
const ICON_X = BADGE_CENTER_X - ICON_SIZE / 2;
const ICON_Y = BADGE_CENTER_Y - ICON_SIZE / 2;
const TEXT_X = BADGE_CENTER_X;
const NAME_Y = 66;
const NAME_LINE_HEIGHT = 13;
const TYPE_Y = 94;

const toIconTestId = (description: string): string =>
  `attack-path-node-icon-${description
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "")}`;

export const ResourceNode = ({ data, selected }: NodeProps) => {
  const { graphNode, hasFindings } = data as ResourceNodeData;
  const { fillColor, borderColor } = resolveNodeColors({
    labels: graphNode.labels,
    properties: graphNode.properties,
    selected,
    hasFindings,
  });
  const badgeStrokeWidth = selected ? 4 : hasFindings ? 3 : 1.5;
  const glowRadius = selected ? 31 : hasFindings ? 29 : 0;
  const glowOpacity = selected ? 0.32 : hasFindings ? 0.26 : 0;
  const visual = resolveNodeVisual(graphNode);
  const Icon = visual.Icon;

  const displayNameLines = getNodeLabelLines(
    visual.displayName,
    NAME_MAX_CHARS,
    NAME_MAX_LINES,
  );
  const typeLabel = visual.description;
  const iconLabel = `${visual.description} icon`;

  return (
    <>
      <HiddenHandles
        sourcePosition={Position.Bottom}
        sourceStyle={{ top: BADGE_BOTTOM_Y }}
        style={{ left: BADGE_CENTER_X }}
        targetPosition={Position.Top}
        targetStyle={{ top: BADGE_TOP_Y }}
      />
      <svg width={NODE_WIDTH} height={NODE_HEIGHT} className="overflow-visible">
        {glowRadius > 0 && (
          <circle
            cx={BADGE_CENTER_X}
            cy={BADGE_CENTER_Y}
            r={glowRadius}
            fill={borderColor}
            fillOpacity={glowOpacity}
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
          strokeWidth={badgeStrokeWidth}
          className={selected ? "selected-node" : undefined}
        />
        <g
          aria-label={iconLabel}
          data-testid={toIconTestId(visual.description)}
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
        <text
          x={TEXT_X}
          y={NAME_Y}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#ffffff"
          style={{ textShadow: "0 1px 2px rgba(0,0,0,0.5)" }}
          pointerEvents="none"
        >
          {displayNameLines.map((line, index) => (
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
          {typeLabel && (
            <tspan
              x={TEXT_X}
              y={TYPE_Y}
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
