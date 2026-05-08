"use client";

import { Handle, Position } from "@xyflow/react";
import type { CSSProperties } from "react";

interface HiddenHandlesProps {
  sourcePosition?: Position;
  style?: CSSProperties;
  targetPosition?: Position;
  sourceStyle?: CSSProperties;
  targetStyle?: CSSProperties;
}

export const HiddenHandles = ({
  sourcePosition = Position.Bottom,
  sourceStyle,
  style,
  targetPosition = Position.Top,
  targetStyle,
}: HiddenHandlesProps) => (
  <>
    <Handle
      type="target"
      position={targetPosition}
      className="invisible"
      style={{ ...style, ...targetStyle }}
    />
    <Handle
      type="source"
      position={sourcePosition}
      className="invisible"
      style={{ ...style, ...sourceStyle }}
    />
  </>
);
