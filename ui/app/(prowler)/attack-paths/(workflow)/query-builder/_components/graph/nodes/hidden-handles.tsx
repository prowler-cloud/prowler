"use client";

import { Handle, Position } from "@xyflow/react";

export const HiddenHandles = () => (
  <>
    <Handle type="target" position={Position.Left} className="invisible" />
    <Handle type="source" position={Position.Right} className="invisible" />
  </>
);
