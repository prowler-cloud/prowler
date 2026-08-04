"use client";

import { type NodeProps, Position } from "@xyflow/react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { GraphNode } from "@/types/attack-paths";

import { resolveNodeColors, resolveNodeVisual } from "../../../_lib";
import { FINDING_NODE_DIMENSIONS } from "../../../_lib/node-dimensions";
import { getNodeLabelDisplay } from "../../../_lib/node-label-lines";

import { HiddenHandles } from "./hidden-handles";

interface FindingNodeData {
  graphNode: GraphNode;
  [key: string]: unknown;
}

const NODE_WIDTH = FINDING_NODE_DIMENSIONS.WIDTH;
const NODE_HEIGHT = FINDING_NODE_DIMENSIONS.HEIGHT;
const TITLE_MAX_CHARS = FINDING_NODE_DIMENSIONS.LABEL_MAX_CHARS;
const TITLE_MAX_LINES = FINDING_NODE_DIMENSIONS.LABEL_MAX_LINES;
const BADGE_SIZE = 44;
const BADGE_RADIUS = BADGE_SIZE / 2;
const BADGE_CENTER_X = NODE_WIDTH / 2;
const BADGE_CENTER_Y = 26;
const BADGE_LEFT_X = BADGE_CENTER_X - BADGE_RADIUS;
const BADGE_RIGHT_X = BADGE_CENTER_X + BADGE_RADIUS;
const ICON_SIZE = 28;
const ICON_X = BADGE_CENTER_X - ICON_SIZE / 2;
const ICON_Y = BADGE_CENTER_Y - ICON_SIZE / 2;
const TEXT_X = BADGE_CENTER_X;
const TITLE_Y = 66;
const TITLE_LINE_HEIGHT = 13;
const SEVERITY_Y = 118;

const severityLabel = (severity: unknown): string | undefined => {
  if (!severity) return undefined;
  const rawSeverity = Array.isArray(severity) ? severity[0] : severity;
  return String(rawSeverity).toLowerCase();
};

const toFindingIconTestId = (severity: string | undefined): string =>
  `attack-path-finding-icon-${severity ?? "unknown"}`;

const toAccessibleSeverity = (severity: string | undefined): string =>
  severity
    ? `${severity.charAt(0).toUpperCase()}${severity.slice(1)}`
    : "Unknown";

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
  const displayTitle = getNodeLabelDisplay(
    title,
    TITLE_MAX_CHARS,
    TITLE_MAX_LINES,
  );
  const visual = resolveNodeVisual(graphNode);
  const Icon = visual.Icon;
  const severity = severityLabel(graphNode.properties?.severity);
  const iconLabel = `${toAccessibleSeverity(severity)} finding risk icon`;

  const badgeStrokeWidth = selected ? 4 : 2.5;
  const glowRadius = selected ? 32 : 30;
  const glowOpacity = selected ? 0.34 : 0.28;
  const nodeSvg = (
    <svg
      width={NODE_WIDTH}
      height={NODE_HEIGHT}
      className="overflow-visible"
      tabIndex={displayTitle.isTruncated ? 0 : undefined}
      data-testid="attack-path-finding-node"
    >
      <circle
        cx={BADGE_CENTER_X}
        cy={BADGE_CENTER_Y}
        r={glowRadius}
        stroke={borderColor}
        strokeOpacity={glowOpacity}
        strokeWidth={8}
        fill={borderColor}
        fillOpacity={glowOpacity / 2}
        pointerEvents="none"
      />
      <circle
        cx={BADGE_CENTER_X}
        cy={BADGE_CENTER_Y}
        r={BADGE_RADIUS}
        fill={fillColor}
        fillOpacity={0.95}
        stroke={borderColor}
        strokeWidth={badgeStrokeWidth}
        className={selected ? "selected-node" : undefined}
      />
      <g
        aria-label={iconLabel}
        data-testid={toFindingIconTestId(severity)}
        role="img"
        transform={`translate(${ICON_X}, ${ICON_Y})`}
      >
        <Icon
          aria-hidden="true"
          color="#ffffff"
          focusable="false"
          height={ICON_SIZE}
          role="presentation"
          size={ICON_SIZE}
          strokeWidth={2.4}
          width={ICON_SIZE}
        />
      </g>
      <text
        x={TEXT_X}
        y={TITLE_Y}
        textAnchor="middle"
        dominantBaseline="middle"
        fill="#ffffff"
        style={{ textShadow: "0 1px 2px rgba(0,0,0,0.5)" }}
        pointerEvents="none"
      >
        {displayTitle.lines.map((line, index) => (
          <tspan
            key={`${line}-${index}`}
            x={TEXT_X}
            y={TITLE_Y + index * TITLE_LINE_HEIGHT}
            fontSize="11px"
            fontWeight="600"
          >
            {line}
          </tspan>
        ))}
        {severity && (
          <tspan
            x={TEXT_X}
            y={SEVERITY_Y}
            fontSize="9px"
            fill="rgba(255,255,255,0.82)"
          >
            {severity}
          </tspan>
        )}
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
      {displayTitle.isTruncated ? (
        <Tooltip>
          <TooltipTrigger asChild>{nodeSvg}</TooltipTrigger>
          <TooltipContent>{title}</TooltipContent>
        </Tooltip>
      ) : (
        nodeSvg
      )}
    </>
  );
};
