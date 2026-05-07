"use client";

import { Handle, Position } from "@xyflow/react";
import type { CSSProperties } from "react";

interface HiddenHandlesProps {
  style?: CSSProperties;
  sourceStyle?: CSSProperties;
  targetStyle?: CSSProperties;
}

export const HiddenHandles = ({
  sourceStyle,
  style,
  targetStyle,
}: HiddenHandlesProps) => (
  <>
    <Handle
      type="target"
      position={Position.Left}
      className="invisible"
      style={{ ...style, ...targetStyle }}
    />
    <Handle
      type="source"
      position={Position.Right}
      className="invisible"
      style={{ ...style, ...sourceStyle }}
    />
  </>
);
