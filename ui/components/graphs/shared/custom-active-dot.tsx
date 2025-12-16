import { Dot } from "recharts";

import { LineDataPoint } from "../types";

export interface PointClickData {
  point: LineDataPoint;
  dataKey?: string;
}

interface CustomActiveDotProps {
  cx?: number;
  cy?: number;
  payload?: LineDataPoint;
  dataKey: string;
  color: string;
  isFaded: boolean;
  onPointClick?: (data: PointClickData) => void;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}

export const CustomActiveDot = ({
  cx,
  cy,
  payload,
  dataKey,
  color,
  isFaded,
  onPointClick,
  onMouseEnter,
  onMouseLeave,
}: CustomActiveDotProps) => {
  if (cx === undefined || cy === undefined) return null;

  // Don't render active dot for faded lines
  if (isFaded) return null;

  return (
    <Dot
      cx={cx}
      cy={cy}
      r={6}
      fill={color}
      style={{ cursor: onPointClick ? "pointer" : "default" }}
      onClick={() => {
        if (onPointClick && payload) {
          onPointClick({ point: payload, dataKey });
        }
      }}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    />
  );
};
