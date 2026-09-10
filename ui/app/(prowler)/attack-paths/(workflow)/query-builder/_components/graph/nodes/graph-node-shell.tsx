"use client";

import { Position } from "@xyflow/react";
import type { ReactNode } from "react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";

import { HiddenHandles } from "./hidden-handles";

interface GraphNodeShellProps {
  width: number;
  height: number;
  /** Badge center — anchors the hidden left/right connection handles. */
  badgeCenterX: number;
  badgeCenterY: number;
  badgeRadius: number;
  testId: string;
  svgClassName?: string;
  /**
   * Full label to reveal when the on-node text is truncated. When set, the SVG
   * becomes keyboard-focusable and is wrapped in a tooltip; omit it otherwise.
   */
  tooltip?: string;
  children: ReactNode;
}

/**
 * Shared shell for the SVG-drawn attack-path nodes: the sized `<svg>` canvas,
 * the left/right hidden connection handles positioned at the badge edges, and
 * the focusable truncated-label tooltip. Node components supply the badge,
 * icon, and label markup as children.
 */
export const GraphNodeShell = ({
  width,
  height,
  badgeCenterX,
  badgeCenterY,
  badgeRadius,
  testId,
  svgClassName,
  tooltip,
  children,
}: GraphNodeShellProps) => {
  const svg = (
    <svg
      width={width}
      height={height}
      className={cn("overflow-visible", svgClassName)}
      tabIndex={tooltip ? 0 : undefined}
      data-testid={testId}
    >
      {children}
    </svg>
  );

  return (
    <>
      <HiddenHandles
        sourcePosition={Position.Right}
        sourceStyle={{ left: badgeCenterX + badgeRadius, top: badgeCenterY }}
        targetPosition={Position.Left}
        targetStyle={{ left: badgeCenterX - badgeRadius, top: badgeCenterY }}
      />
      {tooltip ? (
        <Tooltip>
          <TooltipTrigger asChild>{svg}</TooltipTrigger>
          <TooltipContent>{tooltip}</TooltipContent>
        </Tooltip>
      ) : (
        svg
      )}
    </>
  );
};
